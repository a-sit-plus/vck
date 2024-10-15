package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.ID_TOKEN
import at.asitplus.openid.OpenIdConstants.ResponseMode.DIRECT_POST
import at.asitplus.openid.OpenIdConstants.ResponseMode.DIRECT_POST_JWT
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.ktor.http.*

internal class AuthorizationRequestValidator {
    @Throws(OAuth2Exception::class)
    fun validateAuthorizationRequest(request: AuthenticationRequestParametersFrom) {
        request.parameters.responseType?.let {
            if (!it.contains(ID_TOKEN) && !it.contains(VP_TOKEN)) {
                Napier.w("createAuthnResponse: Unknown response_type $it")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        } ?: run {
            Napier.w("createAuthnResponse: response_type null in ${request.parameters}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }


        val clientIdScheme = request.parameters.clientIdScheme
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.RedirectUri) {
            request.parameters.verifyClientMetadata()
        }
        if (request.parameters.responseMode.isAnyDirectPost()) {
            request.parameters.verifyResponseModeDirectPost()
        }
        if (clientIdScheme.isAnyX509()) {
            request.verifyClientIdSchemeX509()
        }

        if (!clientIdScheme.isAnyX509()) {
            request.parameters.verifyRedirectUrl()
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyRedirectUrl() {
        if (redirectUrl != null) {
            if (clientId != redirectUrl) {
                Napier.w("client_id does not match redirect_uri")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        }
    }

    private fun OpenIdConstants.ClientIdScheme?.isAnyX509() =
        (this == OpenIdConstants.ClientIdScheme.X509SanDns) || (this == OpenIdConstants.ClientIdScheme.X509SanUri)

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyClientMetadata() {
        if (clientMetadata == null && clientMetadataUri == null) {
            Napier.w("client_id_scheme is redirect_uri, but metadata is not set")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParametersFrom.verifyClientIdSchemeX509() {
        val clientIdScheme = parameters.clientIdScheme
        val responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost()
        val prefix = "client_id_scheme is $clientIdScheme"
        if (this !is AuthenticationRequestParametersFrom.JwsSigned
            || jwsSigned.header.certificateChain == null || jwsSigned.header.certificateChain?.isEmpty() == true
        ) {
            Napier.w("$prefix, but metadata is not set and no x5c certificate chain is present")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        //basic checks done
        val leaf = jwsSigned.header.certificateChain!!.leaf
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            Napier.w("$prefix, but no extensions were found in the leaf certificate")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.X509SanDns) {
            val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames ?: run {
                Napier.w("$prefix, but no dnsNames were found in the leaf certificate")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
            if (!dnsNames.contains(parameters.clientId)) {
                Napier.w("$prefix, but client_id does not match any dnsName in the leaf certificate")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
            if (!responseModeIsDirectPost) {
                val parsedUrl = parameters.redirectUrl?.let { Url(it) } ?: run {
                    Napier.w("$prefix, but no redirect_url was provided")
                    throw OAuth2Exception(Errors.INVALID_REQUEST)
                }
                //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the
                // certificate it may allow the client to freely choose the redirect_uri value
                if (parsedUrl.host != parameters.clientId) {
                    Napier.w("$prefix, but no redirect_url was provided")
                    throw OAuth2Exception(Errors.INVALID_REQUEST)
                }
            }
        } else {
            val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris ?: run {
                Napier.w("$prefix, but no URIs were found in the leaf certificate")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
            if (!uris.contains(parameters.clientId)) {
                Napier.w("$prefix, but client_id does not match any URIs in the leaf certificate")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
            if (parameters.clientId != parameters.redirectUrl) {
                Napier.w("$prefix, but client_id does not match redirect_uri")
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        }
    }

    private fun OpenIdConstants.ResponseMode?.isAnyDirectPost() =
        (this == DIRECT_POST) || (this == DIRECT_POST_JWT)

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.verifyResponseModeDirectPost() {
        if (redirectUrl != null) {
            Napier.w("response_mode is $responseMode, but redirect_url is set")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        if (responseUrl == null) {
            Napier.w("response_mode is $responseMode, but response_url is not set")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
    }
}