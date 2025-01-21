package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.*
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val jwsService: JwsService,
    private val coseService: CoseService,
) {
    suspend fun createPresentationExchangePresentation(
        holder: Holder,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        audience: String,
        presentationDefinition: PresentationDefinition,
        clientMetadata: RelyingPartyMetadata?,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
        jsonWebKeys: Collection<JsonWebKey>?,
    ): KmmResult<PresentationResponseParameters> = catching {
        request.parameters.verifyResponseType()
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null in ${request.parameters}")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
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

        val responseWillBeEncrypted = jsonWebKeys != null && clientMetadata?.requestsEncryption() == true
        val clientId = request.parameters.clientIdWithoutPrefix
        val responseUrl = request.parameters.responseUrl
        val vpRequestParams = PresentationRequestParameters(
            nonce = nonce,
            audience = audience,
            calcIsoDeviceSignature = { docType ->
                calcDeviceSignature(responseWillBeEncrypted, clientId, responseUrl, nonce, docType)
            }
        )
        holder.createPresentation(
            request = vpRequestParams,
            presentationDefinitionId = presentationDefinition.id,
            presentationSubmissionSelection = credentialSubmissions,
        ).getOrElse {
            Napier.w("Could not create presentation", it)
            throw OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED)
        }.also { container ->
            clientMetadata?.vpFormats?.let {
                container.verifyFormatSupport(it)
            }
        }
    }

    /**
     * Performs calculation of the [at.asitplus.wallet.lib.iso.SessionTranscript] and [at.asitplus.wallet.lib.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required in [request] (i.e. it will be encrypted)
     */
    @Throws(PresentationException::class, CancellationException::class)
    private suspend fun calcDeviceSignature(
        responseWillBeEncrypted: Boolean,
        clientId: String?,
        responseUrl: String?,
        nonce: String,
        docType: String,
    ): Pair<CoseSigned<ByteArray>, String?> = if (responseWillBeEncrypted && clientId != null && responseUrl != null) {
        val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        val mdocGeneratedNonce = Random.Default.nextBytes(16).encodeToString(Base16Strict)
        val clientIdToHash =
            ClientIdToHash(clientId = clientId, mdocGeneratedNonce = mdocGeneratedNonce)
        val responseUriToHash = ResponseUriToHash(
            responseUri = responseUrl,
            mdocGeneratedNonce = mdocGeneratedNonce
        )
        val sessionTranscript = SessionTranscript(
            deviceEngagementBytes = null,
            eReaderKeyBytes = null,
            handover = ByteStringWrapper(
                OID4VPHandover(
                    clientIdHash = clientIdToHash.serialize().sha256(),
                    responseUriHash = responseUriToHash.serialize().sha256(),
                    nonce = nonce
                )
            ),
        )
        val deviceAuthentication = DeviceAuthentication(
            type = "DeviceAuthentication",
            sessionTranscript = sessionTranscript,
            docType = docType,
            namespaces = deviceNameSpaceBytes
        )
        Napier.d("Device authentication is ${deviceAuthentication.serialize().encodeToString(Base16())}")
        coseService.createSignedCoseWithDetachedPayload(
            payload = deviceAuthentication.serialize(),
            serializer = ByteArraySerializer(),
            addKeyId = false
        ).getOrElse {
            Napier.w("Could not create DeviceAuth for presentation", it)
            throw PresentationException(it)
        } to mdocGeneratedNonce
    } else {
        coseService.createSignedCose(
            payload = nonce.encodeToByteArray(),
            serializer = ByteArraySerializer(),
            addKeyId = false
        ).getOrElse {
            Napier.w("Could not create DeviceAuth for presentation", it)
            throw PresentationException(it)
        } to null
    }

    suspend fun createSignedIdToken(
        clock: Clock,
        agentPublicKey: CryptoPublicKey,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<JwsSigned<IdToken>?> = catching {
        if (request.parameters.responseType?.contains(OpenIdConstants.ID_TOKEN) != true) {
            return@catching null
        }
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null in ${request.parameters}")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val audience = request.parameters.redirectUrlExtracted
            ?: request.parameters.clientIdWithoutPrefix
            ?: agentJsonWebKey.jwkThumbprint
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
            serializer = IdToken.Companion.serializer(),
            addX5c = false
        ).getOrElse {
            Napier.w("Could not sign id_token", it)
            throw OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseType() {
        if (responseType == null || !responseType!!.contains(OpenIdConstants.VP_TOKEN)) {
            Napier.w("vp_token not requested in response_type='$responseType'")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationDefinition.validateSubmission(
        holder: Holder,
        clientMetadata: RelyingPartyMetadata?,
        credentialSubmissions: Map<String, CredentialSubmission>,
    ) {
        val validator = PresentationSubmissionValidator.Companion.createInstance(this).getOrThrow()
        if (!validator.isValidSubmission(credentialSubmissions.keys)) {
            Napier.w("submission requirements are not satisfied")
            throw OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED)
        }

        // making sure, that all the submissions actually match the corresponding input descriptor requirements
        credentialSubmissions.forEach { submission ->
            val inputDescriptor = this.inputDescriptors.firstOrNull { it.id == submission.key } ?: run {
                Napier.w("Invalid input descriptor id")
                throw OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED)
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
                    throw OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED)
                }
            }
            // TODO: maybe we also want to validate, whether there are any redundant disclosed attributes?
            //  this would be the case if there is only one constraint field with path "$['name']", but two attributes are disclosed
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
            if (supportedFormats.isMissingFormatSupport(descriptor.format)) {
                Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                throw OAuth2Exception(OpenIdConstants.Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
            }
        }

    @Suppress("DEPRECATION")
    private fun FormatHolder.isMissingFormatSupport(claimFormat: ClaimFormat): Boolean {
        return when (claimFormat) {
            ClaimFormat.JWT_VP -> jwtVp?.algorithms?.let { !it.contains(jwsService.algorithm) } ?: false
            ClaimFormat.JWT_SD, ClaimFormat.SD_JWT -> {
                if (jwtSd?.algorithms?.contains(jwsService.algorithm) == false) return true
                if (jwtSd?.sdJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (jwtSd?.kbJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (sdJwt?.algorithms?.contains(jwsService.algorithm) == false) return true
                if (sdJwt?.sdJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (sdJwt?.kbJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                return false
            }

            ClaimFormat.MSO_MDOC -> msoMdoc?.algorithms?.let { !it.contains(jwsService.algorithm) } ?: false
            else -> false
        }
    }
}