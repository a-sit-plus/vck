package at.asitplus.wallet.lib.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import at.asitplus.wallet.lib.validation.Requirement.*

/*
 * Dependency and decision rules of validation, as pure functions over the report model.
 *
 * Parsing and signatures are always required. Trust, timeliness, and status follow the ValidationPolicy. Checks that
 * bind a holder proof to the request (challenge, audience, proof time, ...) are never relaxed, and are
 * REQUIRED_IF_APPLICABLE where the format or transport may not define them.
 *
 * Every rule is a list of named checks with their requirement, which the report records, see
 * ValidationReport.namedChecks: a report is accepted if each of them is satisfied, and its children are accepted.
 */

/** How a check contributes to a decision. */
enum class Requirement {
    /** Only [Passed] satisfies the check. */
    REQUIRED,

    /** [Passed] or [NotApplicable] satisfy the check: it is required where it applies. */
    REQUIRED_IF_APPLICABLE,

    /** The check is recorded, but its outcome does not change the decision. */
    OPTIONAL,
}

/** Whether this outcome satisfies [requirement], i.e. does not reject the report it belongs to. */
internal fun CheckOutcome.satisfies(requirement: Requirement): Boolean = when (requirement) {
    REQUIRED -> this == Passed
    REQUIRED_IF_APPLICABLE -> this == Passed || this == NotApplicable
    OPTIONAL -> true
}

/** Why this outcome did not pass: the cause of [Failed] or [Blocked], if any. */
internal fun CheckOutcome.cause(): Throwable? = when (this) {
    is Failed -> throwable
    is Blocked -> cause
    Passed, NotApplicable -> null
}

/**
 * A check of a report by its [name], the name of its field in the [ValidationChecks], with the [requirement] the policy
 * of the report put on it, see [ValidationReport.namedChecks]. Compound fields are listed by their parts, e.g.
 * `issuerTrust`, `disclosedItems[2].digest`, `status.claim`, `status.mechanisms[0]`, or `status.agreement`, and carry
 * what they refer to, without claim values: the
 * [trust] decision with the selected credential identifier and trust source, the [statusMechanism] with its reference,
 * observed status, and status list token report, or the [disclosedItem].
 */
data class NamedCheck(
    val name: String,
    val outcome: CheckOutcome,
    val requirement: Requirement,
    val trust: TrustValidation? = null,
    val statusMechanism: StatusMechanismValidation? = null,
    val disclosedItem: DisclosedItemReference? = null,
) {
    /** Whether [outcome] satisfies [requirement], i.e. this check does not reject the report. */
    val satisfied: Boolean
        get() = outcome.satisfies(requirement)
}

/**
 * Runs [check] only if this prerequisite passed, otherwise the check is blocked without being evaluated: a check
 * that depends on claims must not run after parsing or signature verification did not pass.
 */
internal inline fun CheckOutcome.ifPassed(check: () -> CheckOutcome): CheckOutcome =
    if (this == Passed) check() else Blocked()

/**
 * This outcome if it failed or is blocked, otherwise [next]: one check made of several parts, e.g. of an artifact and
 * of its certificate, reports the first part that does not pass.
 */
internal inline fun CheckOutcome.andThen(next: () -> CheckOutcome): CheckOutcome =
    if (this is Failed || this is Blocked) this else next()

/**
 * Checks of a credential whose [parsing] or [issuerSignature] did not pass: no claim of it can be relied upon, so
 * every other check is blocked. Trust anchors are selected by the signed credential type, so issuer trust is blocked
 * too, and so are the supplied disclosed items, which are not listed.
 */
internal fun credentialChecksWithoutPrerequisites(
    parsing: CheckOutcome,
    issuerSignature: CheckOutcome,
): CredentialChecks {
    require(parsing != Passed || issuerSignature != Passed) { "At least one prerequisite must not have passed" }
    return CredentialChecks(
        parsing = parsing,
        issuerSignature = parsing.ifPassed { issuerSignature },
        issuerTrust = TrustValidation(Blocked()),
        semantics = Blocked(),
        disclosedItems = emptyList(),
        holderBinding = Blocked(),
        timeliness = TimelinessValidation(Blocked(), details = null),
        status = StatusValidation(claim = Blocked(), agreement = Blocked()),
    )
}

internal fun List<NamedCheck>.allSatisfied() = all { it.satisfied }

/** The cause of the first check that is not satisfied, or a description of it if it has no cause. */
private fun List<NamedCheck>.firstRejection(): Throwable? =
    firstOrNull { !it.satisfied }
        ?.let { it.outcome.cause() ?: IllegalArgumentException("The ${it.name} check did not pass: ${it.outcome}") }

/**
 * Every supplied item has to be valid, there is no partial acceptance of a credential. The holder binding is required
 * as [ValidationPolicy.holderBinding] says.
 */
internal fun CredentialChecks.named(policy: ValidationPolicy) =
    listOf(
        NamedCheck("parsing", parsing, REQUIRED),
        NamedCheck("issuerSignature", issuerSignature, REQUIRED),
        NamedCheck("issuerTrust", issuerTrust.outcome, policy.trust.requirement, trust = issuerTrust),
        NamedCheck("semantics", semantics, REQUIRED),
    ) + disclosedItems.flatMapIndexed { index, item ->
        listOf("parsing" to item.parsing, "digest" to item.digest, "structure" to item.structure)
            .map { (part, outcome) ->
                NamedCheck("disclosedItems[$index].$part", outcome, REQUIRED, disclosedItem = item.reference)
            }
    } + listOf(
        NamedCheck("holderBinding", holderBinding, policy.holderBinding.requirement),
        NamedCheck("timeliness", timeliness.outcome, policy.timelinessRequirement),
    ) + status.named(policy.status)

/** Whether every check that [policy] requires has passed. */
internal fun CredentialChecks.meets(policy: ValidationPolicy): Boolean = named(policy).allSatisfied()

/**
 * Why this report is rejected: the cause of its first check that is not satisfied, in the order of
 * [ValidationReport.namedChecks], or a description of it if the check has no cause, otherwise why its first rejected
 * child is rejected. `null` if the report is accepted.
 */
internal fun ValidationReport.firstRejection(): Throwable? =
    if (decision == ValidationDecision.ACCEPTED) null
    else namedChecks.firstRejection()
        ?: children.firstOrNull { it.decision != ValidationDecision.ACCEPTED }?.firstRejection()
        ?: IllegalArgumentException("The ${checks::class.simpleName} are rejected")

/**
 * The status under [policy]: under [StatusPolicy.Skip] it is recorded only. Otherwise, a claim has to be present if
 * [StatusPolicy.RequireClaim], and if there is one, every advertised mechanism has to yield an accepted status, and
 * all have to agree, which a claim without mechanisms can not. Signer trust is part of each mechanism's outcome,
 * through the report of its status list token, see [statusMechanismValidation].
 */
private fun StatusValidation.named(policy: StatusPolicy): List<NamedCheck> {
    val claimRequirement = when (policy) {
        StatusPolicy.Skip -> OPTIONAL
        is StatusPolicy.ValidateIfPresent -> REQUIRED_IF_APPLICABLE
        is StatusPolicy.RequireClaim -> REQUIRED
    }
    // Without a claim that passed there are no mechanisms, and the claim decides: its parts are only recorded.
    val dependentRequirement = if (policy != StatusPolicy.Skip && claim == Passed) REQUIRED else OPTIONAL
    return listOf(NamedCheck("status.claim", claim, claimRequirement)) +
            mechanisms.mapIndexed { index, mechanism ->
                NamedCheck(
                    name = "status.mechanisms[$index]",
                    outcome = mechanism.outcome,
                    requirement = dependentRequirement,
                    statusMechanism = mechanism,
                )
            } +
            NamedCheck("status.agreement", agreement, dependentRequirement)
}

/** Status list tokens: the signer as [signerTrust] requires, and every other check, including time, always. */
internal fun StatusListTokenChecks.named(signerTrust: TrustPolicy) = listOf(
    NamedCheck("retrieval", retrieval, REQUIRED),
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("signerTrust", this.signerTrust.outcome, signerTrust.requirement, trust = this.signerTrust),
    NamedCheck("subject", subject, REQUIRED),
    NamedCheck("timeliness", timeliness, REQUIRED),
)

/**
 * A presentation has to be parsed; its other checks apply unless the format does not define them or the request
 * requires no proof.
 */
internal fun PresentationChecks.named() = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED_IF_APPLICABLE),
    NamedCheck("proofTime", proofTime, REQUIRED_IF_APPLICABLE),
    NamedCheck("challenge", challenge, REQUIRED_IF_APPLICABLE),
    NamedCheck("audience", audience, REQUIRED_IF_APPLICABLE),
    NamedCheck("presentationBinding", presentationBinding, REQUIRED_IF_APPLICABLE),
)

internal fun ProtocolResponseChecks.named() = listOf(
    NamedCheck("parsing", parsing, REQUIRED_IF_APPLICABLE),
    NamedCheck("encryption", encryption, REQUIRED_IF_APPLICABLE),
    NamedCheck("expectedOrigin", expectedOrigin, REQUIRED_IF_APPLICABLE),
    NamedCheck("requestState", requestState, REQUIRED_IF_APPLICABLE),
    NamedCheck("submissionRequirements", submissionRequirements, REQUIRED_IF_APPLICABLE),
)

/** A JWT proof binds a key to the request, so none of its checks can be relaxed; the nonce applies where provided. */
internal fun JwtProofChecks.named() = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("proofTime", proofTime, REQUIRED),
    NamedCheck("nonce", nonce, REQUIRED_IF_APPLICABLE),
    NamedCheck("audience", audience, REQUIRED),
)

internal fun KeyAttestationChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
) + status.named(policy.status) + NamedCheck("nonce", nonce, REQUIRED_IF_APPLICABLE)

internal fun KeyAttestationChecks.meets(policy: ValidationPolicy): Boolean = named(policy).allSatisfied()

/**
 * The proof of possession can not be relaxed; with DPoP, its time and challenge are checks of the DPoP proof
 * (draft-ietf-oauth-attestation-based-client-auth-10, 6).
 */
internal fun ClientAttestationChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
) + status.named(policy.status) + listOf(
    NamedCheck("clientId", clientId, REQUIRED_IF_APPLICABLE),
    NamedCheck("popSignature", popSignature, REQUIRED),
    NamedCheck("popTime", popTime, REQUIRED_IF_APPLICABLE),
    NamedCheck("audience", audience, REQUIRED_IF_APPLICABLE),
    NamedCheck("challenge", challenge, REQUIRED_IF_APPLICABLE),
)

internal fun ClientAttestationChecks.meets(policy: ValidationPolicy): Boolean = named(policy).allSatisfied()

/**
 * An unsigned request, e.g. with the `redirect_uri` prefix, has neither a signature nor a signer to trust; a signed
 * request has to have its trust evaluated as [policy] requires.
 */
internal fun RequestObjectChecks.named(policy: ValidationPolicy): List<NamedCheck> {
    val trustRequirement = policy.trust.requirement
        .let { if (it == REQUIRED && signature == NotApplicable) REQUIRED_IF_APPLICABLE else it }
    return listOf(
        NamedCheck("parsing", parsing, REQUIRED),
        NamedCheck("signature", signature, REQUIRED_IF_APPLICABLE),
        NamedCheck("trust", trust.outcome, trustRequirement, trust = trust),
        NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
        NamedCheck("clientId", clientId, REQUIRED_IF_APPLICABLE),
        NamedCheck("walletNonce", walletNonce, REQUIRED_IF_APPLICABLE),
        NamedCheck("expectedOrigin", expectedOrigin, REQUIRED_IF_APPLICABLE),
    )
}

internal fun VerifierAttestationChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
    NamedCheck("clientId", clientId, REQUIRED),
)

internal fun RelyingPartyChecks.named() = listOf(NamedCheck("requestData", requestData, REQUIRED))

internal fun AccessCertificateChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
    NamedCheck("clientId", clientId, REQUIRED_IF_APPLICABLE),
)

internal fun RegistrationCertificateChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
) + status.named(policy.status) + listOf(
    NamedCheck("linkage", linkage, REQUIRED),
    NamedCheck("requestAuthorization", requestAuthorization, REQUIRED),
)

internal fun RegistrationCertificateChecks.meets(policy: ValidationPolicy): Boolean = named(policy).allSatisfied()

internal fun IssuerMetadataChecks.named(policy: ValidationPolicy) = listOf(
    NamedCheck("parsing", parsing, REQUIRED),
    NamedCheck("signature", signature, REQUIRED),
    NamedCheck("trust", trust.outcome, policy.trust.requirement, trust = trust),
    NamedCheck("timeliness", timeliness, policy.timelinessRequirement),
    NamedCheck("subject", subject, REQUIRED),
)

/**
 * Outcome of the status claim: Not applicable when the policy skips the status, or does not require a claim that is
 * absent, failed when the policy requires an absent claim.
 */
internal fun statusClaimOutcome(policy: StatusPolicy, claimPresent: Boolean): CheckOutcome = when (policy) {
    StatusPolicy.Skip -> NotApplicable
    is StatusPolicy.ValidateIfPresent -> if (claimPresent) Passed else NotApplicable
    is StatusPolicy.RequireClaim -> if (claimPresent) Passed else Failed(IllegalArgumentException("No status claim"))
}

/**
 * Validation of one status mechanism, from the report of its status list [token] and the status [resolved] from it:
 * Blocked if the token is not accepted under the `signerTrust` of [policy], e.g. because it could not be retrieved,
 * is expired, has an invalid signature, or an unauthorized signer, or if the status could not be resolved from it.
 * Failed with [TokenStatusException] if the status is not accepted by [policy], which keeps the status as observed.
 */
internal fun statusMechanismValidation(
    reference: RevocationListInfo,
    token: ValidationReport,
    resolved: KmmResult<TokenStatus>,
    policy: StatusPolicy,
): StatusMechanismValidation {
    val signerTrust = requireNotNull(policy.signerTrustOrNull) { "Status is not validated when skipping status" }
    val accepted = requireNotNull(policy.acceptedOrNull) { "Status is not validated when skipping status" }
    val checks = token.checks as? StatusListTokenChecks
        ?: throw IllegalArgumentException("Token has to be a status list token report")
    require(token.decision == ValidationReport.statusListToken(checks, signerTrust, token.evaluatedAt).decision) {
        "Token report was evaluated under another signer trust policy"
    }
    // The status of a token that is not accepted is not a verified status, so it is not recorded as observed.
    if (token.decision != ValidationDecision.ACCEPTED) {
        return StatusMechanismValidation(reference, token, Blocked(checks.firstCause(signerTrust)), observed = null)
    }
    return resolved.fold(
        onSuccess = { status ->
            val outcome = if (status in accepted) Passed else Failed(TokenStatusException(status))
            StatusMechanismValidation(reference, token, outcome, observed = status)
        },
        onFailure = { StatusMechanismValidation(reference, token, Blocked(it), observed = null) },
    )
}

/** The cause of the first check that keeps the token from being accepted. */
private fun StatusListTokenChecks.firstCause(signerTrust: TrustPolicy): Throwable? =
    named(signerTrust).filterNot { it.satisfied }.firstNotNullOfOrNull { it.outcome.cause() }

/**
 * Whether all [mechanisms] yield the same status: failed if two of them yield different ones, blocked if one could
 * not be resolved, as agreement can not be established then.
 */
internal fun statusAgreement(mechanisms: List<StatusMechanismValidation>): CheckOutcome {
    if (mechanisms.isEmpty()) return NotApplicable
    val observed = mechanisms.mapNotNull { it.observed }.distinct()
    return when {
        observed.size > 1 -> Failed(IllegalStateException("Token status mechanisms returned conflicting results"))
        mechanisms.any { it.observed == null } -> Blocked()
        else -> Passed
    }
}

/** The trust the signers of status list tokens need under this policy, `null` if the status is skipped. */
internal val StatusPolicy.signerTrustOrNull: TrustPolicy?
    get() = when (this) {
        StatusPolicy.Skip -> null
        is StatusPolicy.ValidateIfPresent -> signerTrust
        is StatusPolicy.RequireClaim -> signerTrust
    }

/** The statuses this policy accepts, `null` if the status is skipped. */
internal val StatusPolicy.acceptedOrNull: Set<TokenStatus>?
    get() = when (this) {
        StatusPolicy.Skip -> null
        is StatusPolicy.ValidateIfPresent -> accepted
        is StatusPolicy.RequireClaim -> accepted
    }

/** The requirement on the trust in a signer: optional for [TrustPolicy.IntegrityOnly]. */
private val TrustPolicy.requirement: Requirement
    get() = when (this) {
        TrustPolicy.IntegrityOnly -> OPTIONAL
        TrustPolicy.RequireAuthorizedSigner -> REQUIRED
    }

/** The requirement on the holder binding of a credential. */
private val HolderBindingPolicy.requirement: Requirement
    get() = when (this) {
        HolderBindingPolicy.None -> OPTIONAL
        HolderBindingPolicy.RequireExpectedKey -> REQUIRED
    }

/** The requirement on the timeliness of an artifact; the time of holder proofs is always required. */
private val ValidationPolicy.timelinessRequirement: Requirement
    get() = if (requireTimeliness) REQUIRED else OPTIONAL
