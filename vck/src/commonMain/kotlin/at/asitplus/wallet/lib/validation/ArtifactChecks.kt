package at.asitplus.wallet.lib.validation

/*
 * Checks of the artifacts besides credentials, presentations and responses. They live here, next to the other
 * checks, because ValidationChecks is sealed; their validators live in the module of their protocol.
 * Wallet providers, relying parties and metadata signers are trusted per artifact kind, so the TrustValidation of
 * these carries no credential identifier.
 */

/**
 * The checks of an OpenID4VCI JWT proof. Its embedded key attestation, if any, is a child report, see
 * [ValidationReport.jwtProof].
 */
data class JwtProofChecks(
    /** `typ`, `alg`, required claims, and at most one of `kid`, `jwk`, `x5c`. */
    val parsing: CheckOutcome,
    /** With the first attested key of an embedded key attestation, otherwise with the key in the header. */
    val signature: CheckOutcome,
    /** `iat`. Never relaxed by the policy, as it protects against replay. */
    val proofTime: CheckOutcome,
    /** A valid, unused `c_nonce`, where the issuer provides one. */
    val nonce: CheckOutcome,
    /** `aud` is the credential issuer. */
    val audience: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a key attestation, either the proof itself (`attestation` proof type) or embedded in a JWT proof.
 */
data class KeyAttestationChecks(
    /** `typ`, `alg`, required claims, e.g. a non-empty `attested_keys`, and `exp` when embedded. */
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    /** Whether the wallet provider is authorized. */
    val trust: TrustValidation,
    /** `iat`, `exp`, and the expiry of `key_storage_status`. */
    val timeliness: CheckOutcome,
    /** The status of `key_storage_status`. */
    val status: StatusValidation,
    /** A valid, unused server-provided `c_nonce`, where the issuer provides one. */
    val nonce: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a client (wallet instance) attestation and its proof of possession, as used for client
 * authentication.
 */
data class ClientAttestationChecks(
    /** Media types and required claims of the attestation and its proof of possession. */
    val parsing: CheckOutcome,
    /** The attestation's signature. */
    val signature: CheckOutcome,
    /** Whether the wallet provider is authorized. */
    val trust: TrustValidation,
    /** `iat`, `exp`, the maximum lifetime, and the expiry of `client_status`. */
    val timeliness: CheckOutcome,
    /** The status of `client_status`. */
    val status: StatusValidation,
    /** `sub` of the attestation is the client identifier. */
    val clientId: CheckOutcome,
    /** The proof of possession is signed with the attestation's `cnf` key, and its `iss` is the attestation's `sub`. */
    val popSignature: CheckOutcome,
    /** `iat` and `exp` of the proof of possession. Never relaxed by the policy. */
    val popTime: CheckOutcome,
    /** `aud` of the proof of possession is this server. */
    val audience: CheckOutcome,
    /** The challenge is valid and consumed. */
    val challenge: CheckOutcome,
) : ValidationChecks

/**
 * The checks of an OpenID4VP authorization request, as received by a wallet. Its verifier attestation and
 * relying-party certificates are child reports, see [ValidationReport.requestObject].
 */
data class RequestObjectChecks(
    /** `typ`, response type and mode, and the parameters of the transport. */
    val parsing: CheckOutcome,
    /** With the key the client identifier prefix establishes. [CheckOutcome.NotApplicable] for unsigned requests. */
    val signature: CheckOutcome,
    /** Whether the relying party is trusted for its client identifier prefix. Not applicable to unsigned requests. */
    val trust: TrustValidation,
    /** `exp` and `nbf`, if present. */
    val timeliness: CheckOutcome,
    /** The client identifier matches what the prefix binds it to, e.g. the DNS name in the signing certificate. */
    val clientId: CheckOutcome,
    /** The `wallet_nonce`, if the wallet sent one. */
    val walletNonce: CheckOutcome,
    /** The calling origin is one of the request's `expected_origins`, over the Digital Credentials API. */
    val expectedOrigin: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a verifier attestation, i.e. of the `verifier_attestation` client identifier prefix.
 */
data class VerifierAttestationChecks(
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    /** Whether the attester is authorized. */
    val trust: TrustValidation,
    val timeliness: CheckOutcome,
    /** `sub` of the attestation is the client identifier. */
    val clientId: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a wallet-relying party as a whole. Its access certificate and registration certificates are child
 * reports, see [ValidationReport.relyingParty].
 */
data class RelyingPartyChecks(
    /** Whether the requested credentials and claims could be extracted from the request. */
    val requestData: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a wallet-relying party access certificate (WRPAC) and the request it signed.
 */
data class AccessCertificateChecks(
    /** The chain is present and the identifier of its leaf parses. */
    val parsing: CheckOutcome,
    /** The request is signed by the leaf, as JAR or as mdoc reader authentication. */
    val signature: CheckOutcome,
    /** Whether the chain leads to an anchor of the access certificate providers. */
    val trust: TrustValidation,
    /** Every certificate of the chain is valid. */
    val timeliness: CheckOutcome,
    /** The `x509_hash` client identifier matches the leaf. Not applicable to mdoc reader authentication. */
    val clientId: CheckOutcome,
) : ValidationChecks

/**
 * The checks of a wallet-relying party registration certificate (WRPRC).
 */
data class RegistrationCertificateChecks(
    /** Media type, algorithm, and required claims. */
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    /** Whether the chain leads to an anchor of the registration certificate providers. */
    val trust: TrustValidation,
    /** `iat`, `exp`, and the maximum validity. */
    val timeliness: CheckOutcome,
    val status: StatusValidation,
    /** `sub` is the identifier of the access certificate. */
    val linkage: CheckOutcome,
    /** The requested credentials and claims are registered. */
    val requestAuthorization: CheckOutcome,
) : ValidationChecks

/**
 * The checks of signed credential issuer metadata, as received by a wallet.
 */
data class IssuerMetadataChecks(
    /** `typ`, decoding, and required claims. */
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    /** Whether the signer is authorized. */
    val trust: TrustValidation,
    /** `iat` and `exp`, if present. */
    val timeliness: CheckOutcome,
    /** `sub` and `credential_issuer` are the identifier the metadata was requested for. */
    val subject: CheckOutcome,
) : ValidationChecks
