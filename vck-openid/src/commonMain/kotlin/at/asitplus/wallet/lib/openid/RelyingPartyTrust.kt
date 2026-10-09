package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.validation.ClientIdentifierTrust
import at.asitplus.wallet.lib.validation.PreRegisteredClients
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.VerifierAttesters

/**
 * A single source of trust in the relying party sending an authorization request, for one client identifier
 * scheme, see [OpenID4VP, Client Identifier Prefixes](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
 *
 * Callers pass a set of these, which in union represents the wallet's trust in relying parties: A request is
 * accepted when *any* source applicable to its client identifier scheme establishes trust. Several sources of the
 * same kind are fine, e.g. a trust list plus a locally pinned certificate.
 *
 * Passing `null` instead of a set means trust is not evaluated at all, i.e. every relying party is trusted. The
 * signature of a signed request is still verified, with the key the request asserts itself (the leaf of `x5c`, a
 * `jwk`, or a `did:key`), so a signed request without one is rejected.
 * Passing an empty set, or a set with no source for the scheme a request uses, rejects that request: Configuring
 * this at all means trust has to be established, and there is no way to do that without trust material. This
 * includes `entity_id` (OpenID Federation) and `did`, for which a [Custom] source is the only way to establish
 * trust, as this library implements neither federation trust chains nor DID resolution — without one, a relying
 * party could bypass the configured trust anchors just by naming itself with a scheme we do not evaluate.
 *
 * Only `redirect_uri` is not covered, as it forbids signed requests anyway, and neither is a request carrying no
 * `client_id` at all, which the DC API authenticates through the platform-provided calling origin instead.
 */
@Deprecated(
    "Configure RelyingPartyValidator with the anchors of the access certificate providers, which establish trust for " +
            "the client identifier prefixes x509_hash and x509_san_dns; trust for other prefixes is not established"
)
@Suppress("DEPRECATION") // its sources refer to it
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
     * (OpenID Federation), `did`, and anything unrecognised. Verify the signature of a signed request with the key
     * the scheme establishes, e.g. from the DID document, and establish trust in the relying party; throw to reject
     * the request, stating why.
     */
    class Custom(
        val evaluate: suspend (RequestParametersFrom<AuthenticationRequestParameters>) -> Unit,
    ) : RelyingPartyTrust
}

/**
 * The [RelyingPartyValidator] establishing the trust these sources established, to migrate from `relyingPartyTrust`:
 * [RelyingPartyTrust.Certificates] become the anchors of the access certificate providers, also if there are none,
 * so that configured trust stays required; [RelyingPartyTrust.PreRegisteredClients] and the verifier attester
 * sources map to theirs. [RelyingPartyTrust.Custom] no longer takes effect, as it decides opaquely instead of
 * returning the keys of the relying party, see [ClientIdentifierTrust].
 */
@Deprecated("Configure RelyingPartyTrustAnchors of a RelyingPartyValidator directly")
@Suppress("DEPRECATION")
fun Set<RelyingPartyTrust>?.toRelyingPartyValidator(): RelyingPartyValidator {
    if (this == null) return RelyingPartyValidator()
    val certificates = filterIsInstance<RelyingPartyTrust.Certificates>()
    val preRegistered = filterIsInstance<RelyingPartyTrust.PreRegisteredClients>()
    val attesterCertificates = filterIsInstance<RelyingPartyTrust.VerifierAttesterCertificates>()
    val attesterKeys = filterIsInstance<RelyingPartyTrust.VerifierAttesterKeys>()
    return RelyingPartyValidator(
        trust = RelyingPartyTrustAnchors(
            accessCertificates = TrustedCertificates { certificates.flatMap { it.certificates() }.toSet() },
            preRegisteredClients = preRegistered.takeIf { it.isNotEmpty() }?.let { sources ->
                PreRegisteredClients { clientId ->
                    sources.flatMap { it.lookup(clientId).orEmpty() }.toCryptoPublicKeys()
                }
            },
            verifierAttesters = VerifierAttesters(
                certificates = attesterCertificates.takeIf { it.isNotEmpty() }
                    ?.let { sources -> TrustedCertificates { sources.flatMap { it.certificates() }.toSet() } },
                keys = attesterKeys.takeIf { it.isNotEmpty() }
                    ?.let { sources -> { sources.flatMap { it.keys() }.toCryptoPublicKeys() } },
            ).takeIf { attesterCertificates.isNotEmpty() || attesterKeys.isNotEmpty() },
        )
    )
}

private fun Collection<JsonWebKey>.toCryptoPublicKeys(): Set<CryptoPublicKey> =
    mapNotNull { it.toCryptoPublicKey().getOrNull() }.toSet()
