package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.OID4VPHandover
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
import at.asitplus.dcapi.request.Oid4vpDCAPIRequest
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatHolder
import at.asitplus.iso.ClientIdToHash
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.ResponseUriToHash
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.cbor.SignCoseFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import io.ktor.utils.io.core.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val supportedAlgorithms: Set<JwsAlgorithm>,
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray>,
    private val signDeviceAuthFallback: SignCoseFun<ByteArray>,
    private val signIdToken: SignJwtFun<IdToken>,
    private val randomSource: RandomSource = RandomSource.Secure,
) {
    suspend fun createPresentation(
        holder: Holder,
        request: AuthenticationRequestParameters,
        nonce: String,
        audience: String,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
        credentialPresentation: CredentialPresentation,
        dcApiRequest: Oid4vpDCAPIRequest?,
    ): KmmResult<PresentationResponseParameters> = catching {
        request.verifyResponseType()

        val requestsDcApiEncryption =
            request.responseMode == OpenIdConstants.ResponseMode.DcApiJwt // TODO enable this check in draft28 branch && clientMetadata?.encryptionSupported() == true
        val responseWillBeEncrypted =
            jsonWebKeys != null && (clientMetadata?.requestsEncryption() == true || requestsDcApiEncryption)
        val clientId = request.clientId
        val responseUrl = request.responseUrl
        val transactionData = request.transactionData
        val mdocGeneratedNonce = if (clientId != null && responseUrl != null) {
            if (responseWillBeEncrypted) randomSource.nextBytes(16).encodeToString(Base64UrlStrict) else ""
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
     * Performs calculation of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
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
        responseWillBeEncrypted: Boolean,
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
                        Napier.d("Device authentication signature input is ${it.encodeToString(Base16())}")
                    }

                signDeviceAuthDetached(
                    protectedHeader = null,
                    unprotectedHeader = null,
                    payload = deviceAuthenticationBytes,
                    serializer = ByteArraySerializer()
                ).getOrElse {
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
                clientIdHash = coseCompliantSerializer.encodeToByteArray(clientIdToHash).sha256(),
                responseUriHash = coseCompliantSerializer.encodeToByteArray(responseUriToHash).sha256(),
                nonce = nonce
            ),
        )
    }

    private fun calcSessionTranscript(
        dcApiRequest: Oid4vpDCAPIRequest,
        nonce: String,
        jsonWebKeys: Collection<JsonWebKey>?,
        responseWillBeEncrypted: Boolean,
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
                hash = coseCompliantSerializer.encodeToByteArray(openID4VPDCAPIHandoverInfo).sha256()
            )
        )
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
            throw AccessDenied("Could not sign id_token", it)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseType() {
        if (responseType == null || !responseType!!.contains(VP_TOKEN)) {
            throw InvalidRequest("response_type invalid: $responseType")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.PresentationExchangeParameters.verifyFormatSupport(
        supportedFormats: FormatHolder,
    ) = presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
        if (!supportedFormats.supportsAlgorithm(descriptor.format)) {
            throw RegistrationValueNotSupported("incompatible algorithms: $supportedFormats")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun PresentationResponseParameters.DCQLParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        verifiablePresentations.entries.mapIndexed { _, descriptor ->
            val format = this.verifiablePresentations.entries.first().value.toFormat()
            if (!supportedFormats.supportsAlgorithm(format)) {
                throw RegistrationValueNotSupported("incompatible algorithms: $supportedFormats")
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
