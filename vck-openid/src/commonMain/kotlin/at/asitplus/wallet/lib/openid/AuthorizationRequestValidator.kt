package at.asitplus.wallet.lib.openid

import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
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
        if (clientIdScheme == ClientIdScheme.RedirectUri) {
            request.parameters.verifyClientMetadata()
        }
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
            is RequestParametersFrom.DcApiSigned<*> -> {
                if (this.parameters.clientId == null)
                    throw InvalidRequest("client_id must be set for DC API signed request")
                this.parameters.verifyExpectedOrigin(this.dcApiRequest.callingOrigin)
            }

            is RequestParametersFrom.DcApiUnsigned<*> -> {
                if (this.parameters.clientId != null)
                    throw InvalidRequest("client_id not allowed for DC API unsigned request")
            }

            else -> throw InvalidRequest("DC API request not set even though response mode is ${parameters.responseMode}")
        }
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.isFromRequestObject(): Boolean =
        this is RequestParametersFrom.Json || this is RequestParametersFrom.JwsSigned

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
    private fun AuthenticationRequestParameters.verifyClientMetadata() {
        if (clientMetadata == null) {
            throw InvalidRequest("client_metadata is null, but client_id_prefix is redirect_uri")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyClientIdPresent() {
        if (clientId == null) {
            throw InvalidRequest("client_id is null")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemeX509() {
        val clientIdScheme = parameters.clientIdSchemeExtracted
        val responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost()
        val responseModeIsDcApi = parameters.responseMode.isAnyDcApi()
        if (this !is RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>
            || jwsSigned.header.certificateChain.isNullOrEmpty()
        ) {
            throw InvalidRequest("x5c is null, and metadata is not set")
        }

        val leaf = jwsSigned.header.certificateChain!!.leaf
        when (clientIdScheme) {
            ClientIdScheme.X509SanDns -> verifyX509SanDns(leaf, responseModeIsDirectPost, responseModeIsDcApi)
            ClientIdScheme.X509Hash -> verifyX509SanHash(leaf)
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

    private fun RequestParametersFrom.RequestParametersSigned<AuthenticationRequestParameters>.verifyX509SanUri(
        leaf: X509Certificate,
    ) {
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw InvalidRequest("no extensions in x5c")
        }
        val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris
            ?: throw InvalidRequest("no SAN in x5c")
        if (!uris.contains(parameters.clientIdWithoutPrefix)) {
            throw InvalidRequest("client_id not in SAN in x5c $uris")
        }
        if (parameters.clientIdWithoutPrefix != parameters.redirectUrl) {
            throw InvalidRequest("client_id not in redirect_uri ${parameters.redirectUrl}")
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