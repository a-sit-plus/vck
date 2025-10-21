package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.OpenID4VPDCAPIHandoverInfo
import at.asitplus.dif.ClaimFormat
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.OpenId4VpHandover
import at.asitplus.iso.OpenId4VpHandoverInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters.DCQLParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters.PresentationExchangeParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.extensions.firstSessionTranscriptThumbprint
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

internal class PresentationFactory(
    private val supportedAlgorithms: Set<SignatureAlgorithm>,
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray>,
    private val signIdToken: SignJwtFun<IdToken>,
    private val randomSource: RandomSource = RandomSource.Secure,
) {
    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull() }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull() }

    suspend fun createPresentation(
        holder: Holder,
        request: AuthenticationRequestParameters,
        nonce: String,
        audience: String,
        clientMetadata: RelyingPartyMetadata?,
        jsonWebKeys: Collection<JsonWebKey>?,
        credentialPresentation: CredentialPresentation,
        dcApiRequestCallingOrigin: String?,
    ): KmmResult<PresentationResponseParameters> = catching {
        request.verifyResponseType()
        val responseWillBeEncrypted = jsonWebKeys != null
                && (clientMetadata?.requestsEncryption() == true || request.responseMode?.requiresEncryption == true)
        val vpRequestParams = PresentationRequestParameters(
            nonce = nonce,
            audience = audience,
            transactionData = request.transactionData,
            calcIsoDeviceSignaturePlain = {
                calcDeviceSignature(
                    clientId = request.clientId,
                    responseUrl = request.responseUrl ?: request.redirectUrlExtracted,
                    nonce = nonce,
                    docType = it.docType,
                    dcApiRequestCallingOrigin = dcApiRequestCallingOrigin,
                    jsonWebKeys = jsonWebKeys,
                    responseWillBeEncrypted = responseWillBeEncrypted
                )
            }
        )

        holder.createPresentation(
            request = vpRequestParams,
            credentialPresentation = credentialPresentation,
        ).getOrElse {
            throw AccessDenied("Could not create presentation", it)
        }.also { presentation ->
            clientMetadata?.vpFormatsSupported?.verifyFormatSupport(presentation)
        }
    }

    private fun VpFormatsSupported.verifyFormatSupport(
        presentation: PresentationResponseParameters,
    ) {
        when (presentation) {
            is DCQLParameters -> presentation.verifyFormatSupport(this)
            is PresentationExchangeParameters -> presentation.verifyFormatSupport(this)
        }
    }


    /**
     * Performs calculation of the [SessionTranscript] and [DeviceAuthentication], according to OpenID4VP 1.0
     */
    @Throws(PresentationException::class, CancellationException::class)
    private suspend fun calcDeviceSignature(
        clientId: String?,
        responseUrl: String?,
        nonce: String,
        docType: String,
        dcApiRequestCallingOrigin: String?,
        jsonWebKeys: Collection<JsonWebKey>?,
        responseWillBeEncrypted: Boolean,
    ): CoseSigned<ByteArray> = signDeviceAuthDetached(
        protectedHeader = null,
        unprotectedHeader = null,
        payload = DeviceAuthentication(
            type = DeviceAuthentication.TYPE,
            sessionTranscript = calcSessionTranscript(
                clientId = clientId,
                responseUrl = responseUrl,
                nonce = nonce,
                dcApiRequestCallingOrigin = dcApiRequestCallingOrigin,
                jsonWebKeys = jsonWebKeys,
                responseWillBeEncrypted = responseWillBeEncrypted
            ),
            docType = docType,
            namespaces = ByteStringWrapper(DeviceNameSpaces(mapOf()))
        ).wrap(),
        serializer = ByteArraySerializer()
    ).getOrElse {
        throw PresentationException("signDeviceAuthDetached failed", it)
    }

    internal fun calcSessionTranscript(
        clientId: String? = null,
        responseUrl: String? = null,
        nonce: String,
        dcApiRequestCallingOrigin: String? = null,
        jsonWebKeys: Collection<JsonWebKey>?,
        responseWillBeEncrypted: Boolean
    ) = if (dcApiRequestCallingOrigin != null) {
        SessionTranscript.forDcApi(
            DCAPIHandover(
                type = DCAPIHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenID4VPDCAPIHandoverInfo>(
                    OpenID4VPDCAPIHandoverInfo(
                        origin = dcApiRequestCallingOrigin,
                        nonce = nonce,
                        jwkThumbprint = if (responseWillBeEncrypted && !jsonWebKeys.isNullOrEmpty()) {
                            jsonWebKeys.firstSessionTranscriptThumbprint()
                        } else null
                    )
                ).sha256()
            )
        )
    } else if (clientId != null && responseUrl != null) {
        SessionTranscript.forOpenId(
            OpenId4VpHandover(
                type = OpenId4VpHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenId4VpHandoverInfo>(
                    OpenId4VpHandoverInfo(
                        clientId = clientId,
                        nonce = nonce,
                        jwkThumbprint = if (responseWillBeEncrypted && !jsonWebKeys.isNullOrEmpty()) {
                            jsonWebKeys.firstSessionTranscriptThumbprint()
                        } else null,
                        responseUrl = responseUrl,
                    )
                ).sha256(),
            ),
        )
    } else {
        throw IllegalStateException("Neither dcApiRequest nor clientId is set")
    }

    private fun DeviceAuthentication.wrap(): ByteArray = coseCompliantSerializer
        .encodeToByteArray(ByteStringWrapper(this))
        .wrapInCborTag(24)
        .also {
            Napier.d("Device authentication signature input is ${it.encodeToString(Base16())}")
        }

    suspend fun createSignedIdToken(
        clock: Clock,
        agentPublicKey: CryptoPublicKey,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<JwsSigned<IdToken>?> = catching {
        if (request.parameters.responseType?.contains(OpenIdConstants.ID_TOKEN) != true) {
            return@catching null
        }
        val nonce = request.parameters.nonce
            ?: throw InvalidRequest("nonce is null")
        val issuedAt = clock.now().truncateToSeconds()
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
            issuedAt = issuedAt,
            expiration = issuedAt + 60.seconds,
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
    private fun PresentationExchangeParameters.verifyFormatSupport(
        supportedFormats: VpFormatsSupported,
    ) = presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
        if (!supportedFormats.supportsAlgorithm(descriptor.format, supportedJwsAlgorithms, supportedCoseAlgorithms)) {
            throw RegistrationValueNotSupported("incompatible algorithms: $supportedFormats")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun DCQLParameters.verifyFormatSupport(supportedFormats: VpFormatsSupported) =
        verifiablePresentations.entries.mapIndexed { _, _ ->
            val format = this.verifiablePresentations.values.flatten().first().toFormat()
            if (!supportedFormats.supportsAlgorithm(format, supportedJwsAlgorithms, supportedCoseAlgorithms)) {
                throw RegistrationValueNotSupported("incompatible algorithms: $supportedFormats")
            }
        }

    private fun CreatePresentationResult.toFormat(): ClaimFormat = when (this) {
        is CreatePresentationResult.DeviceResponse -> ClaimFormat.MSO_MDOC
        is CreatePresentationResult.SdJwt -> ClaimFormat.SD_JWT
        is CreatePresentationResult.Signed -> ClaimFormat.JWT_VP
    }

}

/**
 * Empty objects are fine, since they are not imposing any restrictions on the supported algorithms
 */
internal fun VpFormatsSupported.supportsAlgorithm(
    claimFormat: ClaimFormat,
    supportedJwsAlgorithms: Collection<JwsAlgorithm>,
    supportedCoseAlgorithms: Collection<CoseAlgorithm.Signature>
): Boolean = when (claimFormat) {
    ClaimFormat.JWT_VP -> vcJwt?.let { vcJwt ->
        var result = true
        vcJwt.algorithms?.let {
            result = result and it.any { supportedJwsAlgorithms.contains(it) }
        }
        result
    } ?: false

    ClaimFormat.SD_JWT -> dcSdJwt?.let { dcSdJwt ->
        var result = true
        dcSdJwt.sdJwtAlgorithms?.let {
            result = result and it.any { supportedJwsAlgorithms.contains(it) }
        }
        dcSdJwt.kbJwtAlgorithms?.let {
            result = result and it.any { supportedJwsAlgorithms.contains(it) }
        }
        result
    } ?: false

    ClaimFormat.MSO_MDOC -> msoMdoc?.let { msoMdoc ->
        var result = true // empty object is fine
        msoMdoc.issuerAuthAlgorithms?.let {
            result = result and it.any { supportedCoseAlgorithms.contains(it) }
        }
        msoMdoc.deviceAuthAlgorithms?.let {
            result = result and it.any { supportedCoseAlgorithms.contains(it) }
        }
        result
    } ?: false

    else -> false
}
