package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.CertificateChain

sealed class ClientIdScheme(
    val scheme: OpenIdConstants.ClientIdScheme,
    val clientId: String,
    val redirectUri: String,
    /** Optional parameter, to be used as `iss` for signed authorization requests */
    val issuerUri: String? = clientId
) {
    /**
     * This Client Identifier Scheme allows the Verifier to authenticate using a JWT that is bound to a certain
     * public key. When the Client Identifier Scheme is `verifier_attestation`, the Client Identifier MUST equal
     * the `sub` claim value in the Verifier attestation JWT. The request MUST be signed with the private key
     * corresponding to the public key in the `cnf` claim in the Verifier attestation JWT. This serves as proof of
     * possession of this key. The Verifier attestation JWT MUST be added to the `jwt` JOSE Header of the request
     * object. The Wallet MUST validate the signature on the Verifier attestation JWT. The `iss` claim value of the
     * Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs.
     * If the Wallet cannot establish trust, it MUST refuse the request. If the issuer of the Verifier Attestation
     * JWT adds a `redirect_uris` claim to the attestation, the Wallet MUST ensure the `redirect_uri` request
     * parameter value exactly matches one of the `redirect_uris` claim entries. All Verifier metadata other than
     * the public key MUST be obtained from the `client_metadata` parameter.
     */
    class VerifierAttestation(
        val attestationJwt: JwsSigned<JsonWebToken>,
        redirectUri: String,
    ) : ClientIdScheme(
        scheme = OpenIdConstants.ClientIdScheme.VerifierAttestation,
        clientId = OpenIdConstants.ClientIdScheme.VerifierAttestation.prefix + attestationJwt.payload.subject!!,
        redirectUri = redirectUri
    ) {
        init {
            require(redirectUri.contains(":/"))
        }
    }

    /**
     * When the Client Identifier Scheme is x509_san_dns, the Client Identifier MUST be a DNS name and match a
     * `dNSName` Subject Alternative Name (SAN) [RFC5280](https://www.rfc-editor.org/info/rfc5280) entry in the leaf
     * certificate passed with the request. The request MUST be signed with the private key corresponding to the
     * public key in the leaf X.509 certificate of the certificate chain added to the request in the `x5c` JOSE
     * header [RFC7515](https://www.rfc-editor.org/info/rfc7515) of the signed request object.
     *
     * The Wallet MUST validate the signature and the trust chain of the X.509 certificate.
     * All Verifier metadata other than the public key MUST be obtained from the `client_metadata` parameter.
     * If the Wallet can establish trust in the Client Identifier authenticated through the certificate, e.g.
     * because the Client Identifier is contained in a list of trusted Client Identifiers, it may allow the client
     * to freely choose the `redirect_uri` value. If not, the FQDN of the `redirect_uri` value MUST match the
     * Client Identifier.
     */
    class CertificateSanDns(
        val chain: CertificateChain,
        clientIdDnsName: String,
        redirectUri: String,
    ) : ClientIdScheme(
        scheme = OpenIdConstants.ClientIdScheme.X509SanDns,
        clientId = OpenIdConstants.ClientIdScheme.X509SanDns.prefix + clientIdDnsName,
        redirectUri = redirectUri
    ) {
        init {
            require(chain.first().tbsCertificate.subjectAlternativeNames?.dnsNames?.contains(clientIdDnsName) == true)
        }
    }

    /**
     * This value indicates that the Verifier's Redirect URI (or Response URI when Response Mode `direct_post` is
     * used) is also the value of the Client Identifier. The Authorization Request MUST NOT be signed.
     * The Verifier MAY omit the `redirect_uri` Authorization Request parameter (or `response_uri` when Response
     * Mode `direct_post` is used). All Verifier metadata parameters MUST be passed using the `client_metadata`
     * parameter.
     */
    class RedirectUri(
        redirectUri: String,
    ) : ClientIdScheme(
        scheme = OpenIdConstants.ClientIdScheme.RedirectUri,
        clientId = OpenIdConstants.ClientIdScheme.RedirectUri.prefix + redirectUri,
        redirectUri = redirectUri
    ) {
        init {
            require(redirectUri.contains(":/"))
        }
    }

    /**
     *  This value represents the RFC6749 default behavior, i.e., the Client Identifier needs to be known to the
     *  Wallet in advance of the Authorization Request. The Verifier metadata is obtained using RFC7591 or through
     *  out-of-band mechanisms.
     */
    class PreRegistered(
        clientId: String,
        redirectUri: String,
        /** Optional parameter, to be used as `iss` for signed authorization requests */
        issuerUri: String? = null,
    ) : ClientIdScheme(
        scheme = OpenIdConstants.ClientIdScheme.PreRegistered,
        clientId = clientId,
        redirectUri = redirectUri,
        issuerUri = issuerUri
    ) {
        init {
            require(!clientId.contains(":"))
            require(redirectUri.contains(":/"))
            issuerUri?.let { require(it.contains(":/")) }
        }
    }
}