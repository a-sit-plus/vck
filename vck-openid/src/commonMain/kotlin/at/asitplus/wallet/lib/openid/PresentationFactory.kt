package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters.*
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.coroutines.cancellation.CancellationException

internal class PresentationFactory(
    private val supportedAlgorithms: Set<SignatureAlgorithm>,
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray>,
    @Deprecated("Support for SIOPv2 has been removed")
    private val signIdToken: SignJwtFun<IdToken>,
) {

    private val dcApiSessionTranscript = DcApiSessionTranscriptCalculator()
    private val urlSessionTranscript = UrlSessionTranscriptCalculator()
    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull() }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull() }

    suspend fun createPresentation(
        state: AuthorizationResponsePreparationState,
        holder: Holder,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = catching {
        state.request.parameters.verifyResponseType()
        val nonce = requireNotNull(state.request.parameters.nonce) {
            "nonce parameter is missing in ${state.request.parameters}"
        }
        if (credentialPresentation is CredentialPresentation.IsoDeviceRetrievalPresentation) {
            throw InvalidRequest("ISO Device Retrieval responses are not OpenID4VP presentations")
        }
        val sessionTranscriptCallback = suspend {
            calcSessionTranscript(
                clientId = state.request.parameters.clientId,
                responseUrl = state.request.parameters.responseUrl ?: state.request.parameters.redirectUrlExtracted,
                nonce = nonce,
                dcApiRequestCallingOrigin = state.dcApiCallingOrigin,
                recipientKey = if (state.responseRequiresEncryption)
                    requireNotNull(state.jsonWebKeys?.getEncryptionTargetKey()) {
                        "Could not load recipient key but response requires encryption"
                    }
                else null
            )
        }
        val vpRequestParams = PresentationRequestParameters(
            nonce = nonce,
            audience = state.audience,
            transactionData = state.request.parameters.transactionData,
            calcIsoSessionTranscript = sessionTranscriptCallback,
            calcIsoDeviceSignaturePlain = {
                calcDeviceSignature(
                    sessionTranscriptCallback = sessionTranscriptCallback,
                    docType = it.docType,
                )
            }
        )

        holder.createPresentation(
            request = vpRequestParams,
            credentialPresentation = credentialPresentation,
        ).getOrElse {
            throw AccessDenied("Could not create presentation", it)
        }.also { presentation ->
            state.clientMetadata?.vpFormatsSupported?.verifyFormatSupport(presentation)
        }
    }

    private fun VpFormatsSupported.verifyFormatSupport(
        presentation: PresentationResponseParameters,
    ) {
        when (presentation) {
            is DCQLParameters -> presentation.verifyFormatSupport(this)
            is PresentationExchangeParameters -> presentation.verifyFormatSupport(this)
            is DeviceRetrievalParameters ->
                throw InvalidRequest("ISO Device Retrieval responses are not OpenID4VP presentations")
        }
    }

    /**
     * Performs calculation of the [SessionTranscript] and [DeviceAuthentication], according to OpenID4VP 1.0
     */
    @Throws(PresentationException::class, CancellationException::class)
    private suspend fun calcDeviceSignature(
        sessionTranscriptCallback: suspend () -> SessionTranscript,
        docType: String,
    ): CoseSigned<ByteArray> = signDeviceAuthDetached(
        protectedHeader = null,
        unprotectedHeader = null,
        payload = DeviceAuthentication(
            type = DeviceAuthentication.TYPE,
            sessionTranscript = sessionTranscriptCallback.invoke(),
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
        recipientKey: JsonWebKey? = null
    ) = if (dcApiRequestCallingOrigin != null) {
        dcApiSessionTranscript(
            clientId = clientId,
            nonce = nonce,
            responseUrl = responseUrl,
            clientIdRequired = clientId != null,
            origin = dcApiRequestCallingOrigin,
            recipientKey = recipientKey,
        )
    } else if (clientId != null && responseUrl != null) {
        urlSessionTranscript(
            clientId = clientId,
            nonce = nonce,
            responseUrl = responseUrl,
            clientIdRequired = true,
            origin = dcApiRequestCallingOrigin,
            recipientKey = recipientKey,
        )
    } else {
        throw PresentationException("Neither dcApiRequest nor clientId is set")
    }

    private fun DeviceAuthentication.wrap(): ByteArray = coseCompliantSerializer
        .encodeToByteArray(ByteStringWrapper(this))
        .wrapInCborTag(24)
        .also {
            Napier.d("Device authentication signature input is ${it.encodeToString(Base16())}")
        }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseType() {
        if (responseType == null || !responseType!!.contains(VP_TOKEN)) {
            throw InvalidRequest("response_type invalid: $responseType")
        }
    }

    @Suppress("DEPRECATION")
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
        is CreatePresentationResult.VcJwsPresentationData -> ClaimFormat.JWT_VP
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
