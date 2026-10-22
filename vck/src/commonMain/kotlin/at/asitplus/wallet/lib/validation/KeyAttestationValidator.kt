package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.KEY_ATTESTATION_JWT_TYPE
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.jvm.JvmOverloads
import kotlin.time.Instant

/**
 * Validates key attestations in JWT format (OpenID4VCI 1.0, D.1) of the EUDI Wallet ecosystem (EUDI TS3, 2.3.2),
 * e.g. in the proofs of credential requests, see [validate].
 */
class KeyAttestationValidator @JvmOverloads constructor(
    /**
     * Anchors of the wallet providers, e.g. the issuance anchors of the wallet providers list (`LoteProfile.WALLET`).
     * Without them, trust in wallet providers is blocked.
     */
    private val walletProviderAnchors: TrustedCertificates? = null,
    /**
     * Anchors of the signers of the status lists of key storage components, e.g. the revocation anchors of the
     * wallet providers list. Without them, their signers can not be authorized.
     */
    private val walletProviderStatusAnchors: TrustedCertificates? = null,
    /** Resolves and validates `key_storage_status`. Without a resolver, the status is blocked. */
    private val statusValidator: StatusValidator = StatusValidator(),
    private val signatureCheck: SignatureCheck = SignatureCheck(),
) {

    /** Whether the status of key storage components can be resolved, see [statusValidator]. */
    val resolvesStatus: Boolean
        get() = statusValidator.resolvesStatus

    /**
     * Validates [attestation] under [policy] at [evaluatedAt]:
     *  - `parsing`: `typ` is `key-attestation+jwt`, `alg` an asymmetric signature algorithm (OpenID4VCI 1.0, D.1)
     *    of [supportedAlgorithms] (F.4: "acceptable per local policy"), `attested_keys` is not empty, `exp` is present
     *    if it is [embedded] in a `jwt` proof (D.1), and `key_storage`, `certification`, and `key_storage_status`
     *    are present (EUDI TS3, 2.3.2);
     *  - `signature`: with the signing certificate in `x5c` (EUDI TS3, 2.2.2.2);
     *  - `trust`: the signing certificate is one of [walletProviderAnchors] (ETSI TS 119 472-3 V1.1.1,
     *    CRED-REQ-PROC-4.6.2.1-01), or it is not self-signed and leads to one of them through intermediate
     *    certificates in `x5c`, which does not contain the anchor (EUDI TS3, 2.2.2.2; OpenID4VC HAIP 1.0, 4.5.1);
     *  - `timeliness`: `iat` is not in the future, `exp` and `key_storage_status.exp` are not in the past, the latter
     *    being how long the wallet provider maintains the status (EUDI TS3, 2.4.1);
     *  - `status`: `key_storage_status.status`, resolved only if the key attestation is valid otherwise
     *    (draft-ietf-oauth-status-list-21, 8.3), signed by an anchor of [walletProviderStatusAnchors];
     *  - `nonce`: [nonce], as the protocol checks the `nonce` claim, e.g. against the `c_nonce` of the issuer.
     */
    suspend fun validate(
        attestation: JwsCompactTyped<KeyAttestationJwt>,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
        embedded: Boolean,
        nonce: CheckOutcome,
        supportedAlgorithms: Collection<JwsAlgorithm.Signature>,
    ): KeyAttestationValidationResult {
        val timeScope = TimeScope(evaluatedAt, policy.timeLeeway)
        val payload = attestation.payload
        val verification = signatureCheck.verify(attestation.jws)
        val withoutStatus = KeyAttestationChecks(
            parsing = catching { attestation.requireWellFormed(embedded, supportedAlgorithms) }.toOutcome(),
            signature = if (verification.certificateChain == null) {
                Failed(IllegalArgumentException("The key attestation transports no certificate in x5c"))
            } else verification.outcome,
            trust = walletProviderTrust(verification.certificateChain, walletProviderAnchors, evaluatedAt),
            timeliness = payload.timeliness(timeScope),
            status = StatusValidation(NotApplicable, emptyList(), NotApplicable),
            nonce = nonce,
        )
        val status = walletProviderStatus(
            status = payload.keyStorageStatus?.status,
            artifact = "key attestation",
            otherwiseAccepted = withoutStatus.meets(policy.copy(status = StatusPolicy.Skip)),
            statusValidator = statusValidator,
            statusAnchors = walletProviderStatusAnchors,
            policy = policy,
            evaluatedAt = evaluatedAt,
        )
        val checks = withoutStatus.copy(status = status)
        val report = ValidationReport.keyAttestation(checks, policy, evaluatedAt)
        val attestedKeys = if (report.decision == ValidationDecision.ACCEPTED) {
            payload.attestedKeys.map { it.toCryptoPublicKey().getOrThrow() }
        } else null
        return KeyAttestationValidationResult(report, attestedKeys)
    }

    private fun JwsCompactTyped<KeyAttestationJwt>.requireWellFormed(
        embedded: Boolean,
        supportedAlgorithms: Collection<JwsAlgorithm.Signature>,
    ) {
        require(jws.jwsHeader.type == KEY_ATTESTATION_JWT_TYPE) { "invalid typ: ${jws.jwsHeader.type}" }
        val algorithm = jws.jwsHeader.algorithm
        require(algorithm is JwsAlgorithm.Signature && algorithm in supportedAlgorithms) {
            "unsupported key attestation alg: $algorithm"
        }
        require(payload.attestedKeys.isNotEmpty()) { "key attestation contains no attested_keys" }
        payload.attestedKeys.forEach { it.toCryptoPublicKey().getOrThrow() }
        require(!embedded || payload.expiration != null) { "key attestation in a jwt proof contains no exp" }
        require(!payload.keyStorage.isNullOrEmpty()) { "key attestation contains no key_storage" }
        require(!payload.certification.isNullOrBlank()) { "key attestation contains no certification" }
        requireNotNull(payload.keyStorageStatus) { "key attestation contains no key_storage_status" }
    }

    private fun KeyAttestationJwt.timeliness(timeScope: TimeScope): CheckOutcome = with(timeScope) {
        val expiration = expiration
        val statusExpiration = keyStorageStatus?.expiration
        fun failed(message: String) =
            Failed(TimelinessException(message, now, notBefore = issuedAt, notAfter = expiration))
        when {
            issuedAt.isTooLate() -> failed("issuedAt in future: $issuedAt")
            expiration != null && expiration.isTooEarly() -> failed("expiration in past: $expiration")
            statusExpiration != null && statusExpiration.isTooEarly() ->
                failed("key_storage_status expiration in past: $statusExpiration")

            else -> Passed
        }
    }
}

/** The [report] of a key attestation, and the [attestedKeys] if it has been accepted. */
data class KeyAttestationValidationResult(
    val report: ValidationReport,
    val attestedKeys: List<CryptoPublicKey>?,
) {
    init {
        require(report.checks is KeyAttestationChecks) { "Report has to be a key attestation report" }
        require((attestedKeys != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "Attested keys are present if and only if the report is accepted"
        }
    }
}
