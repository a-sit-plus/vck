package at.asitplus.wallet.lib.validation

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.TrustedCertificates

/**
 * The sources of trust in relying parties, as a wallet, for [RelyingPartyValidator]: per kind of certificate, and per
 * client identifier prefix of OpenID4VP (OpenID4VP 1.0, 5.9.3). A source that is not configured blocks trust for what
 * it covers, so a relying party can not bypass the configured anchors by choosing another prefix.
 */
data class RelyingPartyTrustAnchors(
    /**
     * Anchors of the WRPAC providers, e.g. the issuance anchors of the WRPAC providers list (`LoteProfile.WRPAC`).
     * They also establish trust for the client identifier prefixes `x509_hash` and `x509_san_dns`, whose requests
     * are signed with the access certificate.
     */
    val accessCertificates: TrustedCertificates? = null,
    /** Anchors of the WRPRC providers. */
    val registrationCertificates: TrustedCertificates? = null,
    /** Anchors of the signers of the status lists of WRPRCs. */
    val registrationStatus: TrustedCertificates? = null,
    /** Relying parties known in advance, for the client identifier prefix `pre-registered`. */
    val preRegisteredClients: PreRegisteredClients? = null,
    /** The parties trusted to issue verifier attestations, for the client identifier prefix `verifier_attestation`. */
    val verifierAttesters: VerifierAttesters? = null,
    /**
     * For client identifier prefixes this library does not evaluate itself, e.g. `decentralized_identifier` and
     * `openid_federation`.
     */
    val clientIdentifierPrefixes: ClientIdentifierTrust? = null,
) {
    /** Whether any source of trust for the client identifier of a request is configured. */
    internal val coversClientIdentifiers: Boolean
        get() = accessCertificates != null || preRegisteredClients != null || verifierAttesters != null ||
                clientIdentifierPrefixes != null
}

/** The keys of relying parties known to the wallet in advance, by client identifier. */
fun interface PreRegisteredClients {
    /** The keys registered for [clientId], `null` or empty for a client identifier that is not known. */
    suspend fun keys(clientId: String): Set<CryptoPublicKey>?
}

/**
 * The parties trusted to issue verifier attestations (OpenID4VP 1.0, 12): an attestation transporting its signer in
 * `x5c` is trusted through [certificates], one without through [keys].
 */
data class VerifierAttesters(
    /** Anchors of the attesters: the signing certificate has to be issued by one of them, or be one of them. */
    val certificates: TrustedCertificates? = null,
    /** Keys of the attesters: the attestation has to be signed with one of them. */
    val keys: (suspend () -> Set<CryptoPublicKey>)? = null,
)

/**
 * Establishes trust for a client identifier prefix this library does not evaluate itself, e.g. by resolving the DID
 * of `decentralized_identifier` (OpenID4VP 1.0, 5.9.3), or the trust chain of `openid_federation`.
 */
fun interface ClientIdentifierTrust {
    /**
     * The keys the client identifier of [request] establishes for verifying the signature of the request, which the
     * validator verifies itself. Throw to reject the relying party, stating why.
     */
    suspend fun keys(request: RequestParametersFrom<AuthenticationRequestParameters>): Set<CryptoPublicKey>
}

/**
 * Whether the relying party of a request is trusted for its client identifier prefix, see
 * [RelyingPartyValidator.clientTrust], and the [keys] a trust source established for verifying the signature of the
 * request: for `pre-registered` and prefixes evaluated by [ClientIdentifierTrust]. `null` where the request binds the
 * key itself, i.e. the access certificate or the `cnf` of the verifier attestation, or where trust is not
 * established.
 */
data class ClientTrust(
    val trust: TrustValidation,
    val keys: Set<CryptoPublicKey>? = null,
)
