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
 */

/** How a check contributes to a decision. */
internal enum class Requirement {
    /** Only [Passed] satisfies the check. */
    REQUIRED,

    /** [Passed] or [NotApplicable] satisfy the check: it is required where it applies. */
    REQUIRED_IF_APPLICABLE,

    /** The check is recorded, but its outcome does not change the decision. */
    OPTIONAL,
}

internal fun CheckOutcome.satisfies(requirement: Requirement): Boolean = when (requirement) {
    REQUIRED -> this == Passed
    REQUIRED_IF_APPLICABLE -> this == Passed || this == NotApplicable
    OPTIONAL -> true
}

/**
 * Runs [check] only if this prerequisite passed, otherwise the check is blocked without being evaluated: a check
 * that depends on claims must not run after parsing or signature verification did not pass.
 */
internal inline fun CheckOutcome.ifPassed(check: () -> CheckOutcome): CheckOutcome =
    if (this == Passed) check() else Blocked()

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

/** Whether every check that [policy] and [holderBindingPolicy] require has passed. */
internal fun CredentialChecks.meets(policy: ValidationPolicy, holderBindingPolicy: HolderBindingPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && issuerSignature.satisfies(REQUIRED)
            && issuerTrust.outcome.satisfies(policy.trust.requirement)
            && semantics.satisfies(REQUIRED)
            && disclosedItems.all { it.meetsRequirements() }
            && holderBinding.satisfies(holderBindingPolicy.requirement)
            && timeliness.outcome.satisfies(policy.timelinessRequirement)
            && status.meets(policy.status)

/** Every supplied item has to be valid, there is no partial acceptance of a credential. */
private fun DisclosedItemValidation.meetsRequirements() =
    parsing.satisfies(REQUIRED) && digest.satisfies(REQUIRED) && structure.satisfies(REQUIRED)

internal fun StatusValidation.meets(policy: StatusPolicy): Boolean = when (policy) {
    StatusPolicy.Skip -> true
    is StatusPolicy.ValidateIfPresent -> claim == NotApplicable || mechanismsMeet()
    is StatusPolicy.RequireClaim -> mechanismsMeet()
}

/**
 * Every advertised mechanism has to yield an accepted status, and all have to agree. Signer trust is part of each
 * mechanism's outcome, through the report of its status list token, see [statusMechanismValidation].
 */
private fun StatusValidation.mechanismsMeet(): Boolean =
    claim == Passed && mechanisms.isNotEmpty() && mechanisms.all { it.outcome == Passed } && agreement == Passed

/** Status list tokens: the signer as [signerTrust] requires, and every other check, including time, always. */
internal fun StatusListTokenChecks.meets(signerTrust: TrustPolicy): Boolean =
    requiredOutcomes().all { it.satisfies(REQUIRED) } && this.signerTrust.outcome.satisfies(signerTrust.requirement)

private fun StatusListTokenChecks.requiredOutcomes() = listOf(retrieval, parsing, signature, subject, timeliness)

/** All checks of a presentation apply unless the format does not define them or the request requires no proof. */
internal fun PresentationChecks.satisfied(): Boolean =
    listOf(parsing, signature, proofTime, challenge, audience, presentationBinding)
        .all { it.satisfies(REQUIRED_IF_APPLICABLE) }

internal fun ProtocolResponseChecks.satisfied(): Boolean =
    listOf(parsing, encryption, expectedOrigin, requestState, submissionRequirements)
        .all { it.satisfies(REQUIRED_IF_APPLICABLE) }

/** A JWT proof binds a key to the request, so none of its checks can be relaxed; the nonce applies where provided. */
internal fun JwtProofChecks.satisfied(): Boolean =
    listOf(parsing, signature, proofTime, audience).all { it.satisfies(REQUIRED) }
            && nonce.satisfies(REQUIRED_IF_APPLICABLE)

internal fun KeyAttestationChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && status.meets(policy.status)
            && nonce.satisfies(REQUIRED_IF_APPLICABLE)

internal fun ClientAttestationChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && status.meets(policy.status)
            && listOf(clientId, popSignature, popTime, audience, challenge).all { it.satisfies(REQUIRED) }

/**
 * An unsigned request, e.g. with the `redirect_uri` prefix, has neither a signature nor a signer to trust; a signed
 * request has to have its trust evaluated as [policy] requires.
 */
internal fun RequestObjectChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED_IF_APPLICABLE)
            && (signature == NotApplicable && trust.outcome == NotApplicable
            || trust.outcome.satisfies(policy.trust.requirement))
            && timeliness.satisfies(policy.timelinessRequirement)
            && listOf(clientId, walletNonce, expectedOrigin).all { it.satisfies(REQUIRED_IF_APPLICABLE) }

internal fun VerifierAttestationChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && clientId.satisfies(REQUIRED)

internal fun RelyingPartyChecks.satisfied(): Boolean = requestData.satisfies(REQUIRED)

internal fun AccessCertificateChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && clientId.satisfies(REQUIRED_IF_APPLICABLE)

internal fun RegistrationCertificateChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && status.meets(policy.status)
            && linkage.satisfies(REQUIRED)
            && requestAuthorization.satisfies(REQUIRED)

internal fun IssuerMetadataChecks.meets(policy: ValidationPolicy): Boolean =
    parsing.satisfies(REQUIRED)
            && signature.satisfies(REQUIRED)
            && trust.outcome.satisfies(policy.trust.requirement)
            && timeliness.satisfies(policy.timelinessRequirement)
            && subject.satisfies(REQUIRED)

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
    (requiredOutcomes().filterNot { it.satisfies(REQUIRED) } +
            listOf(this.signerTrust.outcome).filterNot { it.satisfies(signerTrust.requirement) })
        .firstNotNullOfOrNull { it.cause() }

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

private val TrustPolicy.requirement: Requirement
    get() = when (this) {
        TrustPolicy.IntegrityOnly -> OPTIONAL
        TrustPolicy.RequireAuthorizedSigner -> REQUIRED
    }

private val HolderBindingPolicy.requirement: Requirement
    get() = when (this) {
        HolderBindingPolicy.None -> OPTIONAL
        HolderBindingPolicy.RequireExpectedKey -> REQUIRED
    }

private val ValidationPolicy.timelinessRequirement: Requirement
    get() = if (requireTimeliness) REQUIRED else OPTIONAL

private fun CheckOutcome.cause(): Throwable? = when (this) {
    is Failed -> throwable
    is Blocked -> cause
    Passed, NotApplicable -> null
}
