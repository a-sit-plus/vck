package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * Validates client attestations, i.e. wallet attestations (OpenID4VCI 1.0, E) of the EUDI Wallet ecosystem (Wallet
 * Instance Attestations, EUDI TS3, 2.3.1), as used for attestation-based client authentication
 * (draft-ietf-oauth-attestation-based-client-auth-10), see [validate].
 */
class ClientAttestationValidator @JvmOverloads constructor(
    /**
     * Anchors of the wallet providers, e.g. the issuance anchors of the wallet providers list (`LoteProfile.WALLET`).
     * Without them, trust in wallet providers is blocked.
     */
    private val walletProviderAnchors: TrustedCertificates? = null,
    /**
     * Anchors of the signers of the status lists of wallet instances, e.g. the revocation anchors of the wallet
     * providers list. Without them, their signers can not be authorized.
     */
    private val walletProviderStatusAnchors: TrustedCertificates? = null,
    /** Resolves and validates `client_status`. Without a resolver, the status is blocked. */
    private val statusValidator: StatusValidator = StatusValidator(),
    private val signatureCheck: SignatureCheck = SignatureCheck(),
) {

    /** Whether the status of wallet instances can be resolved, see [statusValidator]. */
    val resolvesStatus: Boolean
        get() = statusValidator.resolvesStatus

    /**
     * Validates [attestation] together with the checks of its proof of possession, [possession], under [policy] at
     * [evaluatedAt]:
     *  - `parsing`: `typ` is `oauth-client-attestation+jwt`, `alg` an asymmetric signature algorithm of
     *    [supportedAlgorithms], `sub` and `exp` are present, and `cnf` contains a public key
     *    (draft-ietf-oauth-attestation-based-client-auth-10, 5.1, 5.2); `x5c` is present (OpenID4VC HAIP 1.0, 4.4.1);
     *    `wallet_name`, `wallet_version`, `wallet_solution_certification_information`, and `client_status` are
     *    present (EUDI TS3, 2.3.1); and the proof of possession is well-formed, see [ClientAttestationPossession];
     *  - `signature`: with the signing certificate in `x5c` (EUDI TS3, 2.2.1.2);
     *  - `trust`: the signing certificate is issued by one of [walletProviderAnchors], which are not transported
     *    (OpenID4VC HAIP 1.0, 4.4.1);
     *  - `timeliness`: `exp` is not in the past (EUDI TS3, 2.2.1.2), `iat`, which is optional, not in the future, the
     *    lifetime less than 24 hours (EUDI TS3, 2.2.1.1), and `client_status.exp` not in the past, being how long the
     *    wallet provider maintains the status (EUDI TS3, 2.4.1);
     *  - `status`: `client_status.status`, resolved only if the attestation is valid otherwise
     *    (draft-ietf-oauth-status-list-21, 8.3), signed by an anchor of [walletProviderStatusAnchors];
     *  - `clientId`: `sub` is the [clientId] of the request, if any (draft-ietf-oauth-attestation-based-client-auth-10,
     *    5.1); not applicable without one;
     *  - `popSignature`, `popTime`, `audience`, `challenge`: [possession], as the protocol checks the proof of
     *    possession, e.g. against the challenges of the authorization server.
     */
    suspend fun validate(
        attestation: JwsCompactTyped<JsonWebToken>,
        clientId: String?,
        possession: ClientAttestationPossession,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
        supportedAlgorithms: Collection<JwsAlgorithm.Signature>,
    ): ClientAttestationValidationResult {
        val payload = attestation.payload
        val verification = signatureCheck.verify(attestation.jws)
        val withoutStatus = ClientAttestationChecks(
            parsing = catching { attestation.requireWellFormed(supportedAlgorithms) }.toOutcome()
                .takeIf { it != Passed } ?: possession.parsing,
            signature = if (verification.certificateChain == null) {
                Failed(IllegalArgumentException("client attestation has no x5c"))
            } else verification.outcome,
            trust = walletProviderTrust(verification.certificateChain, walletProviderAnchors, evaluatedAt),
            timeliness = payload.timeliness(TimeScope(evaluatedAt, policy.timeLeeway)),
            status = StatusValidation(NotApplicable, emptyList(), NotApplicable),
            clientId = when {
                clientId == null -> NotApplicable
                payload.subject == null -> Blocked()
                payload.subject == clientId -> Passed
                else -> Failed(IllegalArgumentException("subject not equal to client_id"))
            },
            popSignature = possession.signature,
            popTime = possession.time,
            audience = possession.audience,
            challenge = possession.challenge,
        )
        val status = walletProviderStatus(
            status = payload.clientStatus?.status,
            artifact = "client attestation",
            otherwiseAccepted = withoutStatus.meets(policy.copy(status = StatusPolicy.Skip)),
            statusValidator = statusValidator,
            statusAnchors = walletProviderStatusAnchors,
            policy = policy,
            evaluatedAt = evaluatedAt,
        )
        val report = ValidationReport.clientAttestation(withoutStatus.copy(status = status), policy, evaluatedAt)
        val confirmationKey = if (report.decision == ValidationDecision.ACCEPTED) {
            payload.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrThrow()
        } else null
        return ClientAttestationValidationResult(report, confirmationKey)
    }

    private fun JwsCompactTyped<JsonWebToken>.requireWellFormed(
        supportedAlgorithms: Collection<JwsAlgorithm.Signature>,
    ) {
        require(jws.jwsHeader.type == JwsContentTypeConstants.CLIENT_ATTESTATION_JWT) {
            "invalid client attestation typ: ${jws.jwsHeader.type}"
        }
        require(!jws.jwsHeader.certificateChain.isNullOrEmpty()) { "client attestation has no x5c" }
        val algorithm = jws.jwsHeader.algorithm
        require(algorithm is JwsAlgorithm.Signature && algorithm in supportedAlgorithms) {
            "unsupported client attestation alg: $algorithm"
        }
        requireNotNull(payload.subject) { "client attestation has no sub" }
        requireNotNull(payload.expiration) { "client attestation has no exp" }
        val confirmationKey = payload.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
        requireNotNull(confirmationKey) { "client attestation has no cnf" }
        require(confirmationKey is CryptoPublicKey.EC || confirmationKey is CryptoPublicKey.RSA) {
            "client attestation confirmation key is not asymmetric"
        }
        require(!payload.walletName.isNullOrBlank()) { "client attestation has no wallet_name" }
        require(!payload.walletVersion.isNullOrBlank()) { "client attestation has no wallet_version" }
        require(!payload.walletSolutionCertificationInformation.isNullOrBlank()) {
            "client attestation has no wallet_solution_certification_information"
        }
        requireNotNull(payload.clientStatus) { "client attestation has no client_status" }
    }

    private fun JsonWebToken.timeliness(timeScope: TimeScope): CheckOutcome = with(timeScope) {
        val issuedAt = issuedAt
        val expiration = expiration ?: return Blocked()
        val statusExpiration = clientStatus?.expiration
        fun failed(message: String) =
            Failed(TimelinessException(message, now, notBefore = issuedAt, notAfter = expiration))
        when {
            issuedAt != null && issuedAt.isTooLate() -> failed("client attestation iat in future: $issuedAt")
            expiration.isTooEarly() -> failed("client attestation expired: $expiration")
            issuedAt != null && expiration - issuedAt >= 24.hours ->
                failed("client attestation lifetime must be less than 24 hours")

            statusExpiration != null && statusExpiration.isTooEarly() ->
                failed("client_status expiration in past: $statusExpiration")

            else -> Passed
        }
    }
}

/**
 * The checks of the proof of possession of a client attestation, made by the protocol, as they depend on its
 * transport: a client attestation PoP JWT, or a DPoP proof (draft-ietf-oauth-attestation-based-client-auth-10, 5.2,
 * 6), see [ClientAttestationChecks].
 */
data class ClientAttestationPossession(
    /** The media type and required claims of the proof of possession, [CheckOutcome.Passed] if it has none. */
    val parsing: CheckOutcome,
    val signature: CheckOutcome,
    val time: CheckOutcome,
    val audience: CheckOutcome,
    val challenge: CheckOutcome,
)

/** The [report] of a client attestation, and its [confirmationKey] if it has been accepted. */
data class ClientAttestationValidationResult(
    val report: ValidationReport,
    val confirmationKey: CryptoPublicKey?,
) {
    init {
        require(report.checks is ClientAttestationChecks) { "Report has to be a client attestation report" }
        require((confirmationKey != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "The confirmation key is present if and only if the report is accepted"
        }
    }
}
