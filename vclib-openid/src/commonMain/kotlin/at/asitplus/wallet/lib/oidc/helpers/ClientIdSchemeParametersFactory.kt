package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.ktor.http.Url


class ClientIdSchemeParametersFactory(val request: AuthenticationRequestParametersFrom<*>) {
    fun createClientIdSchemeParameters(): KmmResult<ClientIdSchemeParameters?> {
        return KmmResult.runCatching {
            when (request.parameters.clientIdScheme) {
                OpenIdConstants.ClientIdScheme.X509_SAN_DNS -> createX509SanDnsClientIdSchemeParameters()
                OpenIdConstants.ClientIdScheme.X509_SAN_URI -> createX509SanUriClientIdSchemeParameters()
                else -> createOtherClientIdSchemeParameters(request.parameters.clientIdScheme)
            }
        }.wrap()
    }

    private fun createOtherClientIdSchemeParameters(clientIdScheme: OpenIdConstants.ClientIdScheme?): ClientIdSchemeParameters.OtherClientIdSchemeParameters? {
        if (request.parameters.redirectUrl != null) {
            if (request.parameters.clientId != request.parameters.redirectUrl) {
                Napier.w("client_id does not match redirect_uri")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }
        }
        return clientIdScheme?.let {
            ClientIdSchemeParameters.OtherClientIdSchemeParameters(clientIdScheme)
        }
    }

    private fun createX509SanDnsClientIdSchemeParameters(): ClientIdSchemeParameters.X509ClientIdSchemeParameters.X509SanUriClientIdSchemeParameters {
        val result = validateAndRetrieveX509ClientIdSchemeParameters()
        return ClientIdSchemeParameters.X509ClientIdSchemeParameters.X509SanUriClientIdSchemeParameters(
            leaf = result
        )
    }

    private fun createX509SanUriClientIdSchemeParameters(): ClientIdSchemeParameters.X509ClientIdSchemeParameters.X509SanDnsClientIdSchemeParameters {
        val result = validateAndRetrieveX509ClientIdSchemeParameters()
        return ClientIdSchemeParameters.X509ClientIdSchemeParameters.X509SanDnsClientIdSchemeParameters(
            leaf = result
        )
    }

    private fun validateAndRetrieveX509ClientIdSchemeParameters(): X509Certificate {
        if (request.parameters.clientMetadata == null || request !is AuthenticationRequestParametersFrom.JwsSigned || request.source.header.certificateChain == null || request.source.header.certificateChain?.isEmpty() == true) {
            Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but metadata is not set and no x5c certificate chain is present in the original authn request")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }

        val leaf = request.source.header.certificateChain!!.leaf
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions?.isEmpty() == true) {
            Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but no extensions were found in the leaf certificate")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        if (request.parameters.clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) {
            val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames ?: run {
                Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but no dnsNames were found in the leaf certificate")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }

            if (!dnsNames.contains(request.parameters.clientId)) {
                Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but client_id does not match any dnsName in the leaf certificate")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }

            if (request.parameters.responseMode != OpenIdConstants.ResponseMode.DIRECT_POST && request.parameters.responseMode != OpenIdConstants.ResponseMode.DIRECT_POST_JWT) {
                val parsedUrl = request.parameters.redirectUrl?.let { Url(it) } ?: run {
                    Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but no redirect_url was provided")
                    throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
                }

                //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the certificate it may allow the client to freely choose the redirect_uri value
                if (parsedUrl.host != request.parameters.clientId) {
                    Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but no redirect_url was provided")
                    throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
                }
            }
        } else {
            val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris ?: run {
                Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but no URIs were found in the leaf certificate")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }
            if (!uris.contains(request.parameters.clientId)) {
                Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but client_id does not match any URIs in the leaf certificate")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }

            if (request.parameters.clientId != request.parameters.redirectUrl) {
                Napier.w("client_id_scheme is ${request.parameters.clientIdScheme}, but client_id does not match redirect_uri")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }
        }
        return leaf
    }
}