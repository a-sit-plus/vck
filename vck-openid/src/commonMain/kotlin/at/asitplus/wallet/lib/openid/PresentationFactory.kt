package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.ClaimFormat
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
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

internal class PresentationFactory(
    private val supportedAlgorithms: Set<SignatureAlgorithm>,
) {

    @Deprecated(
        message = "signDeviceAuthDetached is no longer used, because Iso Device Signature has been moved into" +
                " Holder's presentation creation. Support for SIOPv2 has been removed",
        replaceWith = ReplaceWith( expression = "PresentationFactory(supportedAlgorithms)", ),
    )
    constructor(
        supportedAlgorithms: Set<SignatureAlgorithm>,
        signDeviceAuthDetached:  SignCoseDetachedFun<ByteArray>,
        signIdToken: SignJwtFun<IdToken>
    ) : this(supportedAlgorithms)

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
        @Suppress("DEPRECATION")
        if (credentialPresentation is CredentialPresentation.PresentationExchangePresentation) {
            throw InvalidRequest("Presentation Exchange presentations are not supported by OpenID4VP")
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
            result = result and it.any { it.matchesAny(supportedCoseAlgorithms) }
        }
        msoMdoc.deviceAuthAlgorithms?.let {
            result = result and it.any { it.matchesAny(supportedCoseAlgorithms) }
        }
        result
    } ?: false

    else -> false
}

private fun CoseAlgorithm.matchesAny(algorithms: Collection<CoseAlgorithm.Signature>) =
    this is CoseAlgorithm.Signature && algorithms.any { it.legacyEquivalent() == legacyEquivalent() }

private fun CoseAlgorithm.Signature.legacyEquivalent() = when (this) {
    CoseAlgorithm.Signature.ESP256 -> CoseAlgorithm.Signature.ES256
    CoseAlgorithm.Signature.ESP384 -> CoseAlgorithm.Signature.ES384
    CoseAlgorithm.Signature.ESP512 -> CoseAlgorithm.Signature.ES512
    else -> this
}
