package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.agent.TrustedCertificates

/**
 * How a wallet establishes trust in the relying party sending an authorization request, per client identifier
 * scheme, see [OpenID4VP, Client Identifier Prefixes](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
 *
 * Every source is optional, but a request using a scheme whose source is not configured is rejected: Configuring
 * this at all means trust in the relying party has to be established, and there is no way to do that for a scheme
 * we have no trust material for.
 *
 * Not covered, i.e. these schemes are accepted without evaluating trust in the relying party even when this is
 * configured: `redirect_uri` (which forbids signed requests anyway), `entity_id` (OpenID Federation) and `did`,
 * as this library implements neither federation trust chains nor DID resolution.
 */
class RelyingPartyTrust(
    /**
     * Trust anchors for the certificate chain transported in the `x5c` header of requests using the
     * `x509_san_dns` or `x509_hash` client identifier scheme.
     */
    val certificates: TrustedCertificates? = null,
    /**
     * Certificates of the parties trusted to issue verifier attestations, for the `verifier_attestation` client
     * identifier scheme. Applies when the attestation transports its signer in an `x5c` header.
     */
    val verifierAttesterCertificates: TrustedCertificates? = null,
    /**
     * Keys of the parties trusted to issue verifier attestations, for the `verifier_attestation` client
     * identifier scheme. Applies when the attestation asserts no certificate.
     */
    val verifierAttesterKeys: (suspend () -> Set<JsonWebKey>)? = null,
    /**
     * Keys of relying parties known to this wallet in advance, looked up by their client identifier, for the
     * `pre-registered` client identifier scheme. Return `null` for an unknown client identifier.
     */
    val preRegisteredClients: (suspend (clientId: String) -> Set<JsonWebKey>?)? = null,
    /**
     * Consulted for client identifier schemes this library does not evaluate natively, i.e. `entity_id`
     * (OpenID Federation), `did`, and anything unrecognised. Throw to reject the request.
     *
     * In contrast to the deprecated [at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier] this receives the
     * whole request, so it also covers DC API and multi-signed requests, and it states why it rejected one.
     */
    val custom: (suspend (RequestParametersFrom<AuthenticationRequestParameters>) -> Unit)? = null,
)
