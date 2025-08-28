package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.request.Oid4vpDCAPIRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import io.ktor.http.*
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

        if (request.parameters.responseMode.isAnyDcApi() && request is RequestParametersFrom.JwsSigned) {
            if (request.dcApiRequest == null || request.dcApiRequest !is Oid4vpDCAPIRequest) {
                throw InvalidRequest("DC API request not set even though response mode is dcapi")
            }
            val dcApiRequest = request.dcApiRequest as Oid4vpDCAPIRequest
            request.parameters.verifyClientIdPresent()
            request.parameters.verifyExpectedOrigin(dcApiRequest.callingOrigin)
        }

        val clientIdScheme = request.parameters.clientIdSchemeExtracted
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.RedirectUri) {
            request.parameters.verifyClientMetadata()
        }
        if (request.parameters.responseMode.isAnyDirectPost()) {
            request.parameters.verifyResponseModeDirectPost()
        }
        if (clientIdScheme.isAnyX509()) {
            request.verifyClientIdSchemeX509()
        }
        if (clientIdScheme is OpenIdConstants.ClientIdScheme.RedirectUri) {
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

    @Suppress("DEPRECATION")
    private fun OpenIdConstants.ClientIdScheme?.isAnyX509() =
        (this == OpenIdConstants.ClientIdScheme.X509SanDns) || (this == OpenIdConstants.ClientIdScheme.X509SanUri)

    @Suppress("DEPRECATION")
    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyClientMetadata() {
        if (clientMetadata == null && clientMetadataUri == null) {
            throw InvalidRequest("client_metadata is null, but client_id_scheme is redirect_uri")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyClientIdPresent() {
        if (clientId == null) {
            throw InvalidRequest("client_id is null")
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyExpectedOrigin(actualOrigin: String?) {
        expectedOrigins.run {
            if (this == null || !this.contains(actualOrigin)) {
                throw InvalidRequest("origin $actualOrigin not in expected_origins")
            }
        }
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParametersFrom<AuthenticationRequestParameters>.verifyClientIdSchemeX509() {
        val clientIdScheme = parameters.clientIdSchemeExtracted
        val responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost()
        val responseModeIsDcApi = parameters.responseMode.isAnyDcApi()
        val prefix = "client_id_scheme is $clientIdScheme"
        if (this !is RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>
            || jwsSigned.header.certificateChain == null || jwsSigned.header.certificateChain?.isEmpty() == true
        ) {
            throw InvalidRequest("x5c is null, and metadata is not set")
        }
        //basic checks done
        val leaf = jwsSigned.header.certificateChain!!.leaf
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw InvalidRequest("no extensions in x5c")
        }
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.X509SanDns) {
            val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames ?: run {
                throw InvalidRequest("no dnsNames in x5c")
            }
            if (!dnsNames.contains(parameters.clientIdWithoutPrefix)) {
                throw InvalidRequest("client_id not in dnsNames in x5c $dnsNames")
            }
            if (!responseModeIsDirectPost && !responseModeIsDcApi) {
                val parsedUrl = parameters.redirectUrl?.let { Url(it) } ?: run {
                    throw InvalidRequest("redirect_uri is null")
                }
                //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the
                // certificate it may allow the client to freely choose the redirect_uri value
                if (parsedUrl.host != parameters.clientIdWithoutPrefix) {
                    throw InvalidRequest("client_id not in redirect_uri $parsedUrl")
                }
            }
        } else {
            val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris ?: run {
                throw InvalidRequest("no SAN in x5c")
            }
            if (!uris.contains(parameters.clientIdWithoutPrefix)) {
                throw InvalidRequest("client_id not in SAN in x5c $uris")
            }
            if (parameters.clientIdWithoutPrefix != parameters.redirectUrl) {
                throw InvalidRequest("client_id not in redirect_uri ${parameters.redirectUrl}")
            }
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