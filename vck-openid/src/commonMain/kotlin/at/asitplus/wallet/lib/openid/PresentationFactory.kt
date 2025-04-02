package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationDefinition
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.DeprecatedBase64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val jwsService: JwsService,
    private val coseService: CoseService,
) {
    suspend fun createPresentation(
        holder: Holder,
        request: RequestParameters,
        nonce: String,
        audience: String,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = catching {
        request.verifyResponseType()

        val responseWillBeEncrypted = jsonWebKeys != null && clientMetadata?.requestsEncryption() == true
        val clientId = request.clientId
        val responseUrl = request.responseUrl
        val transactionData = parseTransactionData(request)
        val vpRequestParams = PresentationRequestParameters(
            nonce = nonce,
            audience = audience,
            transactionData = transactionData,
            calcIsoDeviceSignature = { docType ->
                calcDeviceSignature(responseWillBeEncrypted, clientId, responseUrl, nonce, docType)
            }
        )

        holder.createPresentation(
            request = vpRequestParams,
            credentialPresentation = credentialPresentation,
        ).getOrElse {
            Napier.w("Could not create presentation", it)
            throw AccessDenied("Could not create presentation", it)
        }.also { presentation ->
            clientMetadata?.vpFormats?.let {
                when (presentation) {
                    is PresentationResponseParameters.DCQLParameters -> presentation.verifyFormatSupport(it)

                    is PresentationResponseParameters.PresentationExchangeParameters -> {
                        presentation.verifyFormatSupport(it)
                    }
                }
            }
        }
    }

    /**
     * Parses all `transaction_data` fields from the request, with a JsonPath, because
     * ... for OpenID4VP Draft 23, that's encoded in the AuthnRequest
     * ... but for Potential UC 5, that's encoded in the input descriptor
     *     and we cannot deserialize into data classes defined in [at.asitplus.rqes]
     *
     * The two standards are not compatible
     * For interoperability if both are present we prefer OpenID over UC5
     */
    private fun parseTransactionData(request: RequestParameters): Pair<PresentationRequestParameters.Flow, Collection<TransactionData>>? {
        val jsonRequest =
            vckJsonSerializer.encodeToJsonElement(PolymorphicSerializer(RequestParameters::class), request)

        val rawTransactionData = JsonPath("$..transaction_data").query(jsonRequest)
            .flatMap { it.value.jsonArray }
            .map { vckJsonSerializer.encodeToString<JsonElement>(it) }
            .ifEmpty { return null }

        val decoded = rawTransactionData.associateWith {
            vckJsonSerializer.decodeFromString<String>(it)
                .decodeToByteArray(Base64UrlStrict)
                .decodeToString()
        }

        val (flow, keysToDecode) = if (decoded.values.any { it.contains("credential_ids") }) {
            PresentationRequestParameters.Flow.OID4VP to decoded.filterValues { it.contains("credential_ids") }.keys
        } else {
            PresentationRequestParameters.Flow.UC5 to decoded.keys
        }

        val transactionData = keysToDecode.mapNotNull { key ->
            runCatching {
                vckJsonSerializer.decodeFromString(DeprecatedBase64URLTransactionDataSerializer, key)
            }.getOrNull()
        }.distinct()

        return flow to transactionData
    }

    /**
     * Performs calculation of the [at.asitplus.wallet.lib.iso.SessionTranscript] and [at.asitplus.wallet.lib.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required in [responseWillBeEncrypted] (i.e. it will be encrypted)
     */
    @Throws(PresentationException::class, CancellationException::class)
    private suspend fun calcDeviceSignature(
        responseWillBeEncrypted: Boolean,
        clientId: String?,
        responseUrl: String?,
        nonce: String,
        docType: String,
    ): Pair<CoseSigned<ByteArray>, String?> = if (clientId != null && responseUrl != null) {
        val deviceNameSpaceBytes = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        // if it's not encrypted, we have no way of transporting the mdocGeneratedNonce, so we'll use the empty string
        val mdocGeneratedNonce = if (responseWillBeEncrypted)
            Random.Default.nextBytes(16).encodeToString(Base64UrlStrict) else ""
        val clientIdToHash = ClientIdToHash(
            clientId = clientId,
            mdocGeneratedNonce = mdocGeneratedNonce
        )
        val responseUriToHash = ResponseUriToHash(
            responseUri = responseUrl,
            mdocGeneratedNonce = mdocGeneratedNonce
        )
        val sessionTranscript = SessionTranscript(
            deviceEngagementBytes = null,
            eReaderKeyBytes = null,
            handover = OID4VPHandover(
                clientIdHash = clientIdToHash.serialize().sha256(),
                responseUriHash = responseUriToHash.serialize().sha256(),
                nonce = nonce
            ),
        )
        val deviceAuthentication = DeviceAuthentication(
            type = "DeviceAuthentication",
            sessionTranscript = sessionTranscript,
            docType = docType,
            namespaces = deviceNameSpaceBytes
        )
        val deviceAuthenticationBytes = coseCompliantSerializer
            .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
            .wrapInCborTag(24)
            .also { Napier.d("Device authentication signature input is ${it.encodeToString(Base16())}") }

        coseService.createSignedCoseWithDetachedPayload(
            payload = deviceAuthenticationBytes,
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

    suspend fun <T : RequestParameters> createSignedIdToken(
        clock: Clock,
        agentPublicKey: CryptoPublicKey,
        request: RequestParametersFrom<T>,
    ): KmmResult<JwsSigned<IdToken>?> = catching {
        if (request.parameters.responseType?.contains(OpenIdConstants.ID_TOKEN) != true) {
            return@catching null
        }
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null in ${request.parameters}")
            throw InvalidRequest("nonce is null")
        }
        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val audience = request.parameters.clientId
            ?: request.parameters.redirectUrlExtracted
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
            serializer = IdToken.serializer(),
            addKeyId = false,
            addX5c = false,
            addJsonWebKey = true,
        ).getOrElse {
            Napier.w("Could not sign id_token", it)
            throw AccessDenied("Could not sign id_token", it)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParameters.verifyResponseType() {
        if (responseType == null || !responseType!!.contains(VP_TOKEN)) {
            Napier.w("vp_token not requested in response_type='$responseType'")
            throw InvalidRequest("response_type invalid")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationDefinition.validateSubmission(
        holder: Holder,
        clientMetadata: RelyingPartyMetadata?,
        credentialSubmissions: Map<String, PresentationExchangeCredentialDisclosure>,
    ) {
        val validator = PresentationSubmissionValidator.createInstance(this).getOrThrow()
        if (!validator.isValidSubmission(credentialSubmissions.keys)) {
            Napier.w("submission requirements are not satisfied")
            throw UserCancelled("submission requirements not satisfied")
        }

        // making sure, that all the submissions actually match the corresponding input descriptor requirements
        credentialSubmissions.forEach { submission ->
            val inputDescriptor = this.inputDescriptors.firstOrNull { it.id == submission.key } ?: run {
                Napier.w("Invalid input descriptor id: ${submission.key}")
                throw UserCancelled("invalid input_descriptor_id")
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
                    throw UserCancelled("constraints not satisfied")
                }
            }
            // TODO: maybe we also want to validate, whether there are any redundant disclosed attributes?
            //  this would be the case if there is only one constraint field with path "$['name']", but two attributes are disclosed
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.PresentationExchangeParameters.verifyFormatSupport(
        supportedFormats: FormatHolder,
    ) =
        presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
            if (supportedFormats.isMissingFormatSupport(descriptor.format)) {
                Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                throw RegistrationValueNotSupported("incompatible algorithms")
            }
        }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.DCQLParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        verifiablePresentations.entries.mapIndexed { _, descriptor ->
            val format = this.verifiablePresentations.entries.first().value.toFormat()
            if (supportedFormats.isMissingFormatSupport(format)) {
                Napier.w("Incompatible JWT algorithms for claim format $format: $supportedFormats")
                throw RegistrationValueNotSupported("incompatible algorithms")
            }
        }

    private fun CreatePresentationResult.toFormat(): ClaimFormat = when (this) {
        is CreatePresentationResult.DeviceResponse -> ClaimFormat.MSO_MDOC
        is CreatePresentationResult.SdJwt -> ClaimFormat.SD_JWT
        is CreatePresentationResult.Signed -> ClaimFormat.JWT_VP
    }

    @Suppress("DEPRECATION")
    private fun FormatHolder.isMissingFormatSupport(claimFormat: ClaimFormat): Boolean {
        return when (claimFormat) {
            ClaimFormat.JWT_VP -> jwtVp?.algorithms?.let { !it.contains(jwsService.algorithm) } ?: false
            ClaimFormat.JWT_SD, ClaimFormat.SD_JWT -> {
                if (jwtSd?.sdJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (jwtSd?.kbJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (sdJwt?.sdJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                if (sdJwt?.kbJwtAlgorithms?.contains(jwsService.algorithm) == false) return true
                return false
            }

            ClaimFormat.MSO_MDOC -> msoMdoc?.algorithms?.let { !it.contains(jwsService.algorithm) } ?: false
            else -> false
        }
    }
}
