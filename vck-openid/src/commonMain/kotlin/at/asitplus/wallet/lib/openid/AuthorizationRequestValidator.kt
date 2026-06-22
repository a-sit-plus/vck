package at.asitplus.wallet.lib.openid

import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsGeneral
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.coroutines.cancellation.CancellationException

internal class AuthorizationRequestValidator(
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
) {
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun validateAuthorizationRequest(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ) {
        request.parameters.responseType?.let {
            if (!it.contains(OpenIdConstants.ID_TOKEN) && !it.contains(OpenIdConstants.VP_TOKEN)) {
                throw InvalidRequest("invalid response_type: $it")
            }
        } ?: throw InvalidRequest("response_type is null")

        if (request.parameters.responseMode.isAnyDcApi()) {
            request.validateDcApi()
        }
        val clientIdScheme = request.parameters.clientIdSchemeExtracted
        if (request.parameters.responseMode.isAnyDirectPost()) {
            request.parameters.verifyResponseModeDirectPost()
        }
        if (clientIdScheme.isAnyX509()) {
            request.verifyClientIdSchemeX509()
        }
        if (clientIdScheme is ClientIdScheme.RedirectUri) {
            request.parameters.verifyRedirectUrl()
        }
        if (request.isFromRequestObject()) {
            request.parameters.walletNonce?.let {
                if (walletNonceMapStore.remove(it) != it) {
                    throw InvalidRequest("wallet_nonce from request not known to us: $it")
                }
            }
        }
        // TODO Verifier Attestation JWT from OpenId4VP 11. also redirect_uri in there
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.validateDcApi() {
        when (this) {
            is RequestParametersFrom.OpenId4VpDcApiSigned,
            is RequestParametersFrom.OpenId4VpDcApiMultiSigned -> {
                val dcApiRequest = this as RequestParametersFrom.DcApiRequest
                if (this.parameters.clientId == null)
                    throw InvalidRequest("client_id must be set for signed DC API request")
                if (this.parameters.expectedOrigins == null)
                    throw InvalidRequest("expected_origins must be set for signed DC API request")
                if (!this.parameters.verifyExpectedOrigin(dcApiRequest.callingOrigin))
                    throw InvalidRequest(
                        "calling origin '${dcApiRequest.callingOrigin}' does not match expected_origins"
                    )
            }

            is RequestParametersFrom.OpenId4VpDcApiUnsigned -> {
                // Nothing to validate: the Wallet authenticates the client through the calling Origin,
                // and any client_id present in an unsigned request is ignored (not used for authentication).
            }

            else -> throw InvalidRequest("DC API request not set even though response mode is ${parameters.responseMode}")
        }
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.isFromRequestObject(): Boolean =
        this is RequestParametersFrom.Json || this is RequestParametersFrom.Jws

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyRedirectUrl() {
        if (redirectUrl != null) {
            if (clientIdWithoutPrefix != redirectUrl) {
                throw InvalidRequest("client_id $clientIdWithoutPrefix not matching redirect_uri $redirectUrl")
            }
        }
    }

    private fun ClientIdScheme?.isAnyX509() =
        (this == ClientIdScheme.X509SanDns) || (this == ClientIdScheme.X509Hash)

    @Throws(OAuth2Exception::class)
    private fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemeX509() {
        val signedRequest = this as? RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>
            ?: throw InvalidRequest("x509 client_id_scheme requires a signed request object")

        val certChain = when (val jws = signedRequest.jwsTyped.jws) {
            is JwsCompact -> jws.jwsHeader.certificateChain
            is JwsGeneral -> jws.signatureElements.firstOrNull()?.jwsHeader?.certificateChain
            else -> null
        }
        val leaf = certChain
            ?.takeIf { it.isNotEmpty() }
            ?.leaf
            ?: throw InvalidRequest("x509 client_id_scheme requires an x5c certificate chain in the JOSE header")

        when (val clientIdScheme = parameters.clientIdSchemeExtracted) {
            ClientIdScheme.X509SanDns -> signedRequest.verifyX509SanDns(
                leaf = leaf,
                responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost(),
                responseModeIsDcApi = parameters.responseMode.isAnyDcApi(),
            )
            ClientIdScheme.X509Hash -> signedRequest.verifyX509SanHash(leaf)
            // checked before calling this method
            else -> throw InvalidRequest("Unexpected clientIdScheme $clientIdScheme")
        }
        // TODO Trust Model: Verify root of trust for certificate chain
    }

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyX509SanDns(
        leaf: X509Certificate,
        responseModeIsDirectPost: Boolean,
        responseModeIsDcApi: Boolean,
    ) {
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw InvalidRequest("no extensions in x5c")
        }
        val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames
            ?: throw InvalidRequest("no dnsNames in x5c")
        if (!dnsNames.contains(parameters.clientIdWithoutPrefix)) {
            throw InvalidRequest("client_id not in dnsNames in x5c $dnsNames")
        }
        if (!responseModeIsDirectPost && !responseModeIsDcApi) {
            val parsedUrl = parameters.redirectUrl?.let { Url(it) }
                ?: throw InvalidRequest("redirect_uri is null")
            //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the
            // certificate it may allow the client to freely choose the redirect_uri value
            if (parsedUrl.host != parameters.clientIdWithoutPrefix) {
                throw InvalidRequest("client_id not in redirect_uri $parsedUrl")
            }
        }
    }

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyX509SanHash(
        leaf: X509Certificate,
    ) {
        val calculatedHash = leaf.encodeToDerSafe()
            .getOrElse { throw InvalidRequest("Could not encode certificate to DER", it) }
            .sha256().encodeToString(Base64UrlStrict)
        if (calculatedHash != parameters.clientIdWithoutPrefix) {
            throw InvalidRequest("hash of certificate (${calculatedHash}) is not equal to client_id")
        }
    }

    private fun OpenIdConstants.ResponseMode?.isAnyDcApi() =
        (this == OpenIdConstants.ResponseMode.DcApi) || (this == OpenIdConstants.ResponseMode.DcApiJwt)

    private fun OpenIdConstants.ResponseMode?.isAnyDirectPost() =
        (this == OpenIdConstants.ResponseMode.DirectPost) || (this == OpenIdConstants.ResponseMode.DirectPostJwt)

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseModeDirectPost() {
        if (redirectUrl != null) {
            throw InvalidRequest("redirect_uri is set, but response_mode is $responseMode")
        }
        if (responseUrl == null) {
            // TODO Verify according to rules of redirect_uri from section 5.10 (this is defined in 7.2)
            throw InvalidRequest("response_url is null, but response_mode is $responseMode")
        }
    }
}
