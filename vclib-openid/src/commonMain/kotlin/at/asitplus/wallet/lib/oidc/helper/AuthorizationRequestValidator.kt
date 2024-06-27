package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.DIRECT_POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.DIRECT_POST_JWT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.ktor.http.Url

internal class AuthorizationRequestValidator(
    val remoteResourceRetriever: RemoteResourceRetrieverFunction
) {
    fun validateAuthorizationRequest(params: AuthenticationRequestParametersFrom<*>) {
        if (params.parameters.responseType == null
            || (!params.parameters.responseType.contains(ID_TOKEN)
                    && !params.parameters.responseType.contains(VP_TOKEN))
        ) {
            Napier.w("createAuthnResponse: Unknown response_type ${params.parameters.responseType}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }

        val clientIdScheme = params.parameters.clientIdScheme
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.REDIRECT_URI) {
            params.parameters.verifyClientMetadata()
        }
        if (params.parameters.responseMode.isAnyDirectPost()) {
            params.parameters.verifyResponseModeDirectPost()
        }
        if (clientIdScheme.isAnyX509()) {
            params.verifyClientIdSchemeX509()
        }

        if (!clientIdScheme.isAnyX509()) {
            params.parameters.verifyRedirectUrl()
        }
    }


    private fun AuthenticationRequestParameters.verifyRedirectUrl() {
        if (redirectUrl != null) {
            if (clientId != redirectUrl)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id does not match redirect_uri") }
        }
    }

    private fun OpenIdConstants.ClientIdScheme?.isAnyX509() =
        (this == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) || (this == OpenIdConstants.ClientIdScheme.X509_SAN_URI)

    private fun AuthenticationRequestParameters.verifyClientMetadata() {
        if (clientMetadata == null && clientMetadataUri == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("client_id_scheme is redirect_uri, but metadata is not set") }
    }

    private fun AuthenticationRequestParametersFrom<*>.verifyClientIdSchemeX509() {
        val clientIdScheme = parameters.clientIdScheme
        val responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost()
        if (this !is AuthenticationRequestParametersFrom.JwsSigned
            || source.header.certificateChain == null
            || source.header.certificateChain!!.isEmpty()
        ) throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("client_id_scheme is $clientIdScheme, but metadata is not set and no x5c certificate chain is present in the original authn request") }
        //basic checks done
        val leaf = source.header.certificateChain!!.leaf
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("client_id_scheme is $clientIdScheme, but no extensions were found in the leaf certificate") }
        }
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) {
            val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but no dnsNames were found in the leaf certificate") }

            if (!dnsNames.contains(parameters.clientId))
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any dnsName in the leaf certificate") }

            if (!responseModeIsDirectPost) {
                val parsedUrl = parameters.redirectUrl?.let { Url(it) }
                    ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
                //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the certificate it may allow the client to freely choose the redirect_uri value
                if (parsedUrl.host != parameters.clientId)
                    throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
            }
        } else {
            val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but no URIs were found in the leaf certificate") }
            if (!uris.contains(parameters.clientId))
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any URIs in the leaf certificate") }

            if (parameters.clientId != parameters.redirectUrl)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match redirect_uri") }
        }
    }

    private fun OpenIdConstants.ResponseMode?.isAnyDirectPost() =
        (this == DIRECT_POST) || (this == DIRECT_POST_JWT)

    private fun AuthenticationRequestParameters.verifyResponseModeDirectPost() {
        if (redirectUrl != null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is $responseMode, but redirect_url is set") }
        if (responseUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is $responseMode, but response_url is not set") }
    }
}