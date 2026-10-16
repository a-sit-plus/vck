package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CredentialValidationInput.*
import at.asitplus.wallet.lib.validation.FormatEvaluation.Evaluated
import at.asitplus.wallet.lib.validation.FormatEvaluation.WithoutPrerequisites
import at.asitplus.wallet.lib.validation.TrustPolicy.IntegrityOnly
import at.asitplus.wallet.lib.validation.TrustPolicy.RequireAuthorizedSigner
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock

/**
 * Validates a single credential, in the format it declares, under an explicit [ValidationPolicy], and reports every
 * check: parsing, the issuer signature, issuer trust per credential type, semantics, every supplied disclosed item,
 * holder binding, time, and status.
 *
 * The validated credential is only returned for an accepted report, see [CredentialValidationResult].
 */
class CredentialValidator @JvmOverloads constructor(
    /** Anchors of the issuers and status list signers per credential type. Without them, trust is blocked. */
    private val trustAnchors: CredentialTrustAnchors? = null,
    /** Resolves and validates the status of credentials. Without a resolver, a status claim is blocked. */
    private val statusValidator: StatusValidator = StatusValidator(),
    private val signatureCheck: SignatureCheck = SignatureCheck(),
    private val clock: Clock = Clock.System,
) {

    /**
     * Validates [input] under [policy]; [holderBinding] decides whether it has to be bound to
     * [CredentialValidationContext.expectedHolderKey]. The clock is read once, all checks use that time.
     */
    @JvmOverloads
    suspend fun validate(
        input: CredentialValidationInput,
        policy: ValidationPolicy,
        holderBinding: HolderBindingPolicy,
        context: CredentialValidationContext = CredentialValidationContext(),
    ): CredentialValidationResult {
        val evaluatedAt = clock.now()
        val timeScope = TimeScope(evaluatedAt, policy.timeLeeway)
        val evaluation = when (input) {
            is VcJwt -> evaluateVcJwt(input, signatureCheck, holderBinding, context, timeScope)
            is SdJwtVc -> evaluateSdJwtVc(input, signatureCheck, holderBinding, context, timeScope)
            is IsoMdoc -> evaluateIsoMdoc(input, signatureCheck, holderBinding, context, timeScope)
        }
        val checks = when (evaluation) {
            is WithoutPrerequisites ->
                credentialChecksWithoutPrerequisites(evaluation.parsing, evaluation.issuerSignature)

            is Evaluated -> checks(evaluation, policy, holderBinding, timeScope)
        }
        val report = ValidationReport.credential(checks, policy, holderBinding, evaluatedAt)
        val credential = (evaluation as? Evaluated)?.credential
            ?.takeIf { report.decision == ValidationDecision.ACCEPTED }
        return CredentialValidationResult(report, credential)
    }

    private suspend fun checks(
        evaluation: Evaluated,
        policy: ValidationPolicy,
        holderBinding: HolderBindingPolicy,
        timeScope: TimeScope,
    ): CredentialChecks {
        val identifier = evaluation.credentialIdentifier
        val issuerTrust = when (policy.trust) {
            IntegrityOnly -> TrustValidation(NotApplicable, identifier)
            RequireAuthorizedSigner -> identifier?.let {
                trustAnchors.checkCredentialTrust(it, TrustPurpose.ISSUANCE, evaluation.certificateChain, timeScope.now)
            } ?: TrustValidation(Blocked(IllegalArgumentException("The credential type is ambiguous")))
        }
        val withoutStatus = CredentialChecks(
            parsing = CheckOutcome.Passed,
            issuerSignature = CheckOutcome.Passed,
            issuerTrust = issuerTrust,
            semantics = evaluation.semantics,
            disclosedItems = evaluation.disclosedItems,
            holderBinding = evaluation.holderBinding,
            timeliness = evaluation.timeliness,
            status = StatusValidation(NotApplicable, emptyList(), NotApplicable),
        )
        return withoutStatus.copy(status = status(evaluation, withoutStatus, policy, holderBinding, timeScope))
    }

    /**
     * The status is only resolved for a credential that is valid otherwise: a Relying Party must not resolve the
     * status of a token it has found invalid already, unless the use case requires it (draft-ietf-oauth-status-list-21,
     * 8.3). So the status is blocked when any other check the policy requires did not pass. With timeliness not
     * required, the status of an expired credential is still resolved.
     */
    private suspend fun status(
        evaluation: Evaluated,
        withoutStatus: CredentialChecks,
        policy: ValidationPolicy,
        holderBinding: HolderBindingPolicy,
        timeScope: TimeScope,
    ): StatusValidation {
        val otherwiseAccepted = withoutStatus.meets(policy.copy(status = StatusPolicy.Skip), holderBinding)
        if (policy.status != StatusPolicy.Skip && evaluation.status != null && !otherwiseAccepted) {
            return StatusValidation(
                claim = Blocked(IllegalStateException("The status of an invalid credential is not resolved")),
                agreement = NotApplicable
            )
        }
        return statusValidator.validate(
            status = evaluation.status,
            signerAnchors = StatusSignerAnchors.OfCredentialType(trustAnchors, evaluation.credentialIdentifier),
            policy = policy.status,
            timeLeeway = policy.timeLeeway,
            evaluatedAt = timeScope.now,
        )
    }
}
