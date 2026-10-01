package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.agent.TrustedCertificates

/**
 * A single source of trust in the relying party sending an authorization request, for one client identifier
 * scheme, see [OpenID4VP, Client Identifier Prefixes](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
 *
 * Callers pass a set of these, which in union represents the wallet's trust in relying parties: A request is
 * accepted when *any* source applicable to its client identifier scheme establishes trust. Several sources of the
 * same kind are fine, e.g. a trust list plus a locally pinned certificate.
 *
 * Passing `null` instead of a set means trust is not evaluated at all, i.e. every relying party is trusted.
 * Passing an empty set, or a set with no source for the scheme a request uses, rejects that request: Configuring
 * this at all means trust has to be established, and there is no way to do that without trust material. This
 * includes `entity_id` (OpenID Federation) and `did`, for which a [Custom] source is the only way to establish
 * trust, as this library implements neither federation trust chains nor DID resolution — without one, a relying
 * party could bypass the configured trust anchors just by naming itself with a scheme we do not evaluate.
 *
 * Only `redirect_uri` is not covered, as it forbids signed requests anyway, and neither is a request carrying no
 * `client_id` at all, which the DC API authenticates through the platform-provided calling origin instead.
 */
sealed interface RelyingPartyTrust {

    /**
     * Trust anchors for the certificate chain transported in the `x5c` header of requests using the
     * `x509_san_dns` or `x509_hash` client identifier scheme.
     */
    class Certificates(
        val certificates: TrustedCertificates,
    ) : RelyingPartyTrust

    /**
     * Certificates of the parties trusted to issue verifier attestations, for the `verifier_attestation` client
     * identifier scheme. Applies when the attestation transports its signer in an `x5c` header.
     */
    class VerifierAttesterCertificates(
        val certificates: TrustedCertificates,
    ) : RelyingPartyTrust

    /**
     * Keys of the parties trusted to issue verifier attestations, for the `verifier_attestation` client
     * identifier scheme. Applies when the attestation asserts no certificate.
     */
    class VerifierAttesterKeys(
        val keys: suspend () -> Set<JsonWebKey>,
    ) : RelyingPartyTrust

    /**
     * Keys of relying parties known to this wallet in advance, looked up by their client identifier, for the
     * `pre-registered` client identifier scheme. Return `null` for an unknown client identifier.
     */
    class PreRegisteredClients(
        val lookup: suspend (clientId: String) -> Set<JsonWebKey>?,
    ) : RelyingPartyTrust

    /**
     * Consulted for client identifier schemes this library does not evaluate natively, i.e. `entity_id`
     * (OpenID Federation), `did`, and anything unrecognised. Throw to reject the request, stating why.
     *
     * In contrast to the deprecated [at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier] this receives the
     * whole request, so it also covers DC API and multi-signed requests, and it states why it rejected one.
     */
    class Custom(
        val evaluate: suspend (RequestParametersFrom<AuthenticationRequestParameters>) -> Unit,
    ) : RelyingPartyTrust
}
