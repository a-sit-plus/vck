package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.IdToken
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.ID_TOKEN
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.CredentialSubmission
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.toDefaultSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val jwsService: JwsService,
) {
    suspend fun createPresentationExchangePresentation(
        holder: Holder,
        request: RequestParameters,
        nonce: String,
        audience: String,
        presentationDefinition: PresentationDefinition,
        clientMetadata: RelyingPartyMetadata?,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<Holder.PresentationResponseParameters> = catching {
        request.verifyResponseType()
        val credentialSubmissions = inputDescriptorSubmissions
            ?: holder.matchInputDescriptorsAgainstCredentialStore(
                inputDescriptors = presentationDefinition.inputDescriptors,
                fallbackFormatHolder = clientMetadata?.vpFormats,
            ).getOrThrow().toDefaultSubmission()

        presentationDefinition.validateSubmission(
            holder = holder,
            clientMetadata = clientMetadata,
            credentialSubmissions = credentialSubmissions
        )

        holder.createPresentation(
            challenge = nonce,
            audienceId = audience,
            // TODO Exact encoding is not specified
            transactionData = request.transactionData?.map { it.encodeToByteArray() },
            presentationDefinitionId = presentationDefinition.id,
            presentationSubmissionSelection = credentialSubmissions,
        ).getOrElse {
            Napier.w("Could not create presentation", it)
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }.also { container ->
            clientMetadata?.vpFormats?.let {
                container.verifyFormatSupport(it)
            }
        }
    }


    suspend fun <T : RequestParameters> createSignedIdToken(
        clock: Clock,
        agentPublicKey: CryptoPublicKey,
        request: RequestParametersFrom<T>,
    ): KmmResult<JwsSigned<IdToken>?> = catching {
        if (request.parameters.responseType?.contains(ID_TOKEN) != true) {
            return@catching null
        }
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null in ${request.parameters}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val audience = request.parameters.redirectUrl ?: request.parameters.clientId ?: agentJsonWebKey.jwkThumbprint
        val idToken = IdToken(
            issuer = agentJsonWebKey.jwkThumbprint,
            subject = agentJsonWebKey.jwkThumbprint,
            subjectJwk = agentJsonWebKey,
            audience = audience,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = nonce,
        )
        jwsService.createSignedJwsAddingParams(
            payload = idToken,
            serializer = IdToken.serializer(),
            addX5c = false
        ).getOrElse {
            Napier.w("Could not sign id_token", it)
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParameters.verifyResponseType() {
        if (responseType == null || !responseType!!.contains(VP_TOKEN)) {
            Napier.w("vp_token not requested in response_type='$responseType'")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationDefinition.validateSubmission(
        holder: Holder,
        clientMetadata: RelyingPartyMetadata?,
        credentialSubmissions: Map<String, CredentialSubmission>,
    ) {
        val validator = PresentationSubmissionValidator.createInstance(this).getOrThrow()
        if (!validator.isValidSubmission(credentialSubmissions.keys)) {
            Napier.w("submission requirements are not satisfied")
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }

        // making sure, that all the submissions actually match the corresponding input descriptor requirements
        credentialSubmissions.forEach { submission ->
            val inputDescriptor = this.inputDescriptors.firstOrNull { it.id == submission.key } ?: run {
                Napier.w("Invalid input descriptor id")
                throw OAuth2Exception(Errors.USER_CANCELLED)
            }

            val constraintFieldMatches = holder.evaluateInputDescriptorAgainstCredential(
                inputDescriptor = inputDescriptor,
                credential = submission.value.credential,
                fallbackFormatHolder = clientMetadata?.vpFormats,
                pathAuthorizationValidator = { true },
            ).getOrThrow()

            val disclosedAttributes = submission.value.disclosedAttributes.map { it.toString() }

            // find a matching path for each constraint field
            constraintFieldMatches.filter {
                // only need to validate non-optional constraint fields
                it.key.optional != true
            }.forEach { constraintField ->
                val allowedPaths = constraintField.value.map {
                    it.normalizedJsonPath.toString()
                }
                disclosedAttributes.firstOrNull { allowedPaths.contains(it) } ?: run {
                    val keyId = constraintField.key.id?.let { " Missing field: $it" }
                    Napier.w("Input descriptor constraints not satisfied: ${inputDescriptor.id}.$keyId")
                    throw OAuth2Exception(Errors.USER_CANCELLED)
                }
            }
            // TODO: maybe we also want to validate, whether there are any redundant disclosed attributes?
            //  this would be the case if there is only one constraint field with path "$['name']", but two attributes are disclosed
        }
    }

    @Throws(OAuth2Exception::class)
    private fun Holder.PresentationResponseParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
            if (supportedFormats.isMissingFormatSupport(descriptor.format)) {
                Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                throw OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
            }
        }

    private fun FormatHolder.isMissingFormatSupport(claimFormat: ClaimFormat) =
        when (claimFormat) {
            ClaimFormat.JWT_VP -> jwtVp?.algorithms?.let { !it.contains(jwsService.algorithm) }
                ?: false

            ClaimFormat.JWT_SD -> jwtSd?.algorithms?.let { !it.contains(jwsService.algorithm) }
                ?: false

            ClaimFormat.MSO_MDOC -> msoMdoc?.algorithms?.let { !it.contains(jwsService.algorithm) }
                ?: false

            else -> false
        }
}