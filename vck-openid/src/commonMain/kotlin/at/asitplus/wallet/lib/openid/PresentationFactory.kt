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
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.SignCoseFun
import at.asitplus.wallet.lib.agent.PresentationRequestParameters.Flow
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.DeprecatedBase64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionValidator
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.dcapi.request.Oid4vpDCAPIRequest
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import io.ktor.utils.io.core.toByteArray
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val supportedAlgorithms: Set<JwsAlgorithm>,
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray>,
    private val signDeviceAuthFallback: SignCoseFun<ByteArray>,
    private val signIdToken: SignJwtFun<IdToken>,
) {
    suspend fun createPresentation(
        holder: Holder,
        request: RequestParameters,
        nonce: String,
        audience: String,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
        credentialPresentation: CredentialPresentation,
        dcApiRequest: Oid4vpDCAPIRequest?
    ): KmmResult<PresentationResponseParameters> = catching {
        request.verifyResponseType()

        val requestsDcApiEncryption = (request as? AuthenticationRequestParameters)?.responseMode == OpenIdConstants.ResponseMode.DcApiJwt // TODO enable this check in draft28 branch && clientMetadata?.encryptionSupported() == true
        val responseWillBeEncrypted = jsonWebKeys != null && (clientMetadata?.requestsEncryption() == true || requestsDcApiEncryption)
        val clientId = request.clientId
        val responseUrl = request.responseUrl
        val transactionData = request.parseTransactionData()
        val mdocGeneratedNonce = if (clientId != null && responseUrl != null) {
            if (responseWillBeEncrypted) Random.nextBytes(16).encodeToString(Base64UrlStrict) else ""
        } else null
        val vpRequestParams = PresentationRequestParameters(
            nonce = nonce,
            audience = audience,
            transactionData = transactionData,
            calcIsoDeviceSignature = { docType, _ ->
                // kept pair result type for backwards compatibility
                calcDeviceSignature(
                    mdocGeneratedNonce,
                    clientId,
                    responseUrl,
                    nonce,
                    docType,
                    dcApiRequest,
                    jsonWebKeys,
                    responseWillBeEncrypted
                ) to null
            },
            mdocGeneratedNonce = mdocGeneratedNonce
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
                    is PresentationResponseParameters.PresentationExchangeParameters ->
                        presentation.verifyFormatSupport(it)
                }
            }
        }
    }

    /**
     * Performs calculation of the [at.asitplus.wallet.lib.iso.SessionTranscript] and [at.asitplus.wallet.lib.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, with the [mdocGeneratedNonce] provided if set,
     * or a fallback mechanism used otherwise
     */
    @Throws(PresentationException::class, CancellationException::class)
    private suspend fun calcDeviceSignature(
        mdocGeneratedNonce: String?,
        clientId: String?,
        responseUrl: String?,
        nonce: String,
        docType: String,
        dcApiRequest: Oid4vpDCAPIRequest?,
        jsonWebKeys: Collection<JsonWebKey>?,
        responseWillBeEncrypted: Boolean
    ): CoseSigned<ByteArray> {
        val sessionTranscript =
            if (dcApiRequest != null) {
                calcSessionTranscript(dcApiRequest, nonce, jsonWebKeys, responseWillBeEncrypted)
            } else if (mdocGeneratedNonce != null && clientId != null && responseUrl != null) {
                calcSessionTranscript(
                    mdocGeneratedNonce,
                    clientId,
                    responseUrl,
                    nonce
                )
            } else {
                null
            }

        return if (sessionTranscript != null) {
            run {
                val deviceAuthentication = DeviceAuthentication(
                    type = "DeviceAuthentication",
                    sessionTranscript = sessionTranscript,
                    docType = docType,
                    namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf()))
                )
                val deviceAuthenticationBytes = coseCompliantSerializer
                    .encodeToByteArray(ByteStringWrapper(deviceAuthentication))
                    .wrapInCborTag(24)
                    .also {
                        Napier.d(
                            "Device authentication signature input is ${
                                it.encodeToString(
                                    Base16()
                                )
                            }"
                        )
                    }

                signDeviceAuthDetached(
                    protectedHeader = null,
                    unprotectedHeader = null,
                    payload = deviceAuthenticationBytes,
                    serializer = ByteArraySerializer()
                ).getOrElse {
                    Napier.w("Could not create DeviceAuth for presentation", it)
                    throw PresentationException(it)
                }
            }
        } else {
            Napier.w("Using signDeviceAuthFallback")
            signDeviceAuthFallback(
                protectedHeader = null,
                unprotectedHeader = null,
                payload = nonce.encodeToByteArray(),
                serializer = ByteArraySerializer()
            ).getOrElse {
                Napier.w("Could not create DeviceAuth for presentation", it)
                throw PresentationException(it)
            }
        }
    }

    private fun calcSessionTranscript(
        mdocGeneratedNonce: String,
        clientId: String,
        responseUrl: String,
        nonce: String,
    ): SessionTranscript {
        val clientIdToHash = ClientIdToHash(
            clientId = clientId,
            mdocGeneratedNonce = mdocGeneratedNonce
        )
        val responseUriToHash = ResponseUriToHash(
            responseUri = responseUrl,
            mdocGeneratedNonce = mdocGeneratedNonce
        )
        return SessionTranscript.forOpenId(
            OID4VPHandover(
                clientIdHash = clientIdToHash.serialize().sha256(),
                responseUriHash = responseUriToHash.serialize().sha256(),
                nonce = nonce
            ),
        )
    }

    private fun calcSessionTranscript(
        dcApiRequest: Oid4vpDCAPIRequest,
        nonce: String,
        jsonWebKeys: Collection<JsonWebKey>?,
        responseWillBeEncrypted: Boolean
    ): SessionTranscript {
        val jwkThumbprint = if (responseWillBeEncrypted && !jsonWebKeys.isNullOrEmpty()) {
            jsonWebKeys.firstOrNull { it.publicKeyUse == "enc" || it.type == JwkType.EC }?.jwkThumbprint
        } else null

        val openID4VPDCAPIHandoverInfo = OpenID4VPDCAPIHandoverInfo(
            dcApiRequest.callingOrigin, nonce, jwkThumbprint?.toByteArray()
        )

        return SessionTranscript.forDcApi(
            DCAPIHandover(
                type = "OpenID4VPDCAPIHandover",
                hash = openID4VPDCAPIHandoverInfo.serialize().sha256()
            )
        )
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
        signIdToken(null, idToken, IdToken.serializer()).getOrElse {
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
    ) = presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
        if (!supportedFormats.supportsAlgorithm(descriptor.format)) {
            Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
            throw RegistrationValueNotSupported("incompatible algorithms")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.DCQLParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        verifiablePresentations.entries.mapIndexed { _, descriptor ->
            val format = this.verifiablePresentations.entries.first().value.toFormat()
            if (!supportedFormats.supportsAlgorithm(format)) {
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
    private fun FormatHolder.supportsAlgorithm(claimFormat: ClaimFormat): Boolean = when (claimFormat) {
        ClaimFormat.JWT_VP -> jwtVp?.algorithms?.any { supportedAlgorithms.contains(it) } == true
        ClaimFormat.JWT_SD, ClaimFormat.SD_JWT ->
            if (jwtSd?.sdJwtAlgorithms?.any { supportedAlgorithms.contains(it) } == true) true
            else if (jwtSd?.kbJwtAlgorithms?.any { supportedAlgorithms.contains(it) } == true) true
            else if (sdJwt?.sdJwtAlgorithms?.any { supportedAlgorithms.contains(it) } == true) true
            else if (sdJwt?.kbJwtAlgorithms?.any { supportedAlgorithms.contains(it) } == true) true
            else false

        ClaimFormat.MSO_MDOC -> msoMdoc?.algorithms?.any { supportedAlgorithms.contains(it) } == true
        else -> false
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
internal fun RequestParameters.parseTransactionData(): Pair<Flow, List<TransactionDataBase64Url>>? {
    val jsonRequest =
        vckJsonSerializer.encodeToJsonElement(PolymorphicSerializer(RequestParameters::class), this)

    val rawTransactionData = JsonPath("$..transaction_data").query(jsonRequest)
        .flatMap { it.value.jsonArray }
        .map { it as JsonPrimitive }
        .ifEmpty { return null }

    //Do not change to map because keys are unordered!
    val oid4vpTransactionData: List<Pair<JsonPrimitive, TransactionData>> = rawTransactionData.map {
        it to vckJsonSerializer.decodeFromJsonElement(DeprecatedBase64URLTransactionDataSerializer, it)
    }.filter { it.second.credentialIds != null }

    return if (oid4vpTransactionData.isNotEmpty()) Flow.OID4VP to oid4vpTransactionData.map { it.first }
    else Flow.UC5 to rawTransactionData
}
