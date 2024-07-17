package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CredentialSubmission
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.toDefaultSubmission
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidc.IdToken
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidc.RelyingPartyMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val jwsService: JwsService,
) {
    suspend fun createPresentationExchangePresentation(
        holder: Holder,
        request: AuthenticationRequestParametersFrom,
        audience: String,
        presentationDefinition: PresentationDefinition,
        clientMetadata: RelyingPartyMetadata?,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<Holder.PresentationResponseParameters> = catching {
        request.parameters.verifyResponseType(presentationDefinition)
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null in ${request.parameters}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        val credentialSubmissions = inputDescriptorSubmissions
            ?: holder.matchInputDescriptorsAgainstCredentialStore(
                inputDescriptors = presentationDefinition.inputDescriptors,
                fallbackFormatHolder = presentationDefinition.formats ?: clientMetadata?.vpFormats,
            ).getOrThrow().toDefaultSubmission()

        presentationDefinition.validateSubmission(
            holder = holder,
            clientMetadata = clientMetadata,
            credentialSubmissions = credentialSubmissions
        )

        holder.createPresentation(
            challenge = nonce,
            audienceId = audience,
            presentationDefinitionId = presentationDefinition.id,
            presentationSubmissionSelection = credentialSubmissions,
        ).getOrElse {
            Napier.w("Could not create presentation", it)
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }.also { container ->
            clientMetadata?.vpFormats?.let { supportedFormats ->
                container.verifyFormatSupport(supportedFormats)
            }
        }
    }


    suspend fun createSignedIdToken(
        clock: Clock,
        agentPublicKey: CryptoPublicKey,
        request: AuthenticationRequestParametersFrom,
    ): KmmResult<JwsSigned?> = catching {
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
        val idToken = IdToken(
            issuer = agentJsonWebKey.jwkThumbprint,
            subject = agentJsonWebKey.jwkThumbprint,
            subjectJwk = agentJsonWebKey,
            audience = request.parameters.redirectUrl ?: request.parameters.clientId
            ?: agentJsonWebKey.jwkThumbprint,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        val signedIdToken = jwsService.createSignedJwsAddingParams(payload = jwsPayload, addX5c = false).getOrElse {
            Napier.w("Could not sign id_token", it)
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }
        signedIdToken
    }


    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseType(presentationDefinition: PresentationDefinition?) {
        if (responseType == null) {
            Napier.w("response_type is not specified")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        if (!responseType.contains(VP_TOKEN) && presentationDefinition == null) {
            Napier.w("vp_token not requested")
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
            val inputDescriptor = this.inputDescriptors.firstOrNull {
                it.id == submission.key
            } ?: run {
                Napier.w("Invalid input descriptor id")
                throw OAuth2Exception(Errors.USER_CANCELLED)
            }

            val constraintFieldMatches = holder.evaluateInputDescriptorAgainstCredential(
                inputDescriptor,
                submission.value.credential,
                fallbackFormatHolder = this.formats ?: clientMetadata?.vpFormats,
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
                disclosedAttributes.firstOrNull {
                    allowedPaths.contains(it)
                } ?: run {
                    Napier.w("Input descriptor constraints not satisfied: ${inputDescriptor.id}.${constraintField.key.id?.let { " Missing field: $it" }}")
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

    private fun FormatHolder.isMissingFormatSupport(claimFormatEnum: ClaimFormatEnum) =
        when (claimFormatEnum) {
            ClaimFormatEnum.JWT_VP -> jwtVp?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) }
                ?: false

            ClaimFormatEnum.JWT_SD -> jwtSd?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) }
                ?: false

            ClaimFormatEnum.MSO_MDOC -> msoMdoc?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) }
                ?: false

            else -> false
        }
}