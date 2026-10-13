package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
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

    /** Whether issuer trust can be decided, i.e. whether [TrustPolicy.RequireAuthorizedSigner] can accept anything. */
    internal val hasTrustAnchors: Boolean
        get() = trustAnchors != null

    /**
     * Validates [input] under [policy], whose [ValidationPolicy.holderBinding] decides whether it has to be bound to
     * [CredentialValidationContext.expectedHolderKey]. The clock is read once, all checks use that time.
     */
    @JvmOverloads
    suspend fun validate(
        input: CredentialValidationInput,
        policy: ValidationPolicy,
        context: CredentialValidationContext = CredentialValidationContext(),
    ): CredentialValidationResult {
        val timeScope = TimeScope(clock.now(), policy.timeLeeway)
        val holderBinding = policy.holderBinding
        val evaluation = when (input) {
            is VcJwt -> evaluateVcJwt(input, signatureCheck, holderBinding, context, timeScope)
            is SdJwtVc -> evaluateSdJwtVc(input, signatureCheck, holderBinding, context, timeScope)
            is IsoMdoc -> evaluateIsoMdoc(input, signatureCheck, holderBinding, context, timeScope)
        }
        return complete(evaluation, policy, timeScope)
    }

    /**
     * Validates the presentation [input] against the request it answers, see [PresentationContext], under [policy]:
     * the holder's proof (key binding JWT, VP-JWT, or mdoc device authentication), and every credential it contains.
     * The clock is read once, all checks use that time. The presentation decides the holder binding of its
     * credentials, so [ValidationPolicy.holderBinding] does not apply.
     */
    suspend fun validate(
        input: PresentationValidationInput,
        context: PresentationContext,
        policy: ValidationPolicy,
    ): PresentationValidationResult {
        val timeScope = TimeScope(clock.now(), policy.timeLeeway)
        val complete = CredentialValidationCompletion { evaluation, holderBinding ->
            complete(evaluation, policy.copy(holderBinding = holderBinding), timeScope)
        }
        val evaluation = when (input) {
            is PresentationValidationInput.SdJwt ->
                evaluateSdJwtPresentation(input, context, signatureCheck, timeScope, complete)

            is PresentationValidationInput.VpJwt ->
                evaluateVpJwtPresentation(input, context, signatureCheck, timeScope, complete)

            is PresentationValidationInput.VcJwt ->
                evaluateVcJwtPresentation(input, context, signatureCheck, timeScope, complete)

            is PresentationValidationInput.MdocDocument ->
                evaluateMdocPresentation(input, context, signatureCheck, timeScope, complete)
        }
        val report = ValidationReport.presentation(
            checks = evaluation.checks,
            credentials = evaluation.credentials.map { it.report },
            evaluatedAt = timeScope.now,
        )
        val presentation = evaluation.presentation?.takeIf { report.decision == ValidationDecision.ACCEPTED }
        return PresentationValidationResult(report, presentation)
    }

    /**
     * The result of a credential the protocol layer could not decode from its transfer encoding, e.g. the base64url
     * encoding of an mdoc in an OpenID4VCI credential response: it is rejected like one that can not be parsed.
     */
    fun rejectUndecodable(
        cause: Throwable,
        policy: ValidationPolicy,
    ): CredentialValidationResult = CredentialValidationResult(
        report = ValidationReport.credential(
            checks = credentialChecksWithoutPrerequisites(parsing = Failed(cause), issuerSignature = Blocked()),
            policy = policy,
            evaluatedAt = clock.now(),
        ),
        credential = null,
    )

    /**
     * The result of a presentation the protocol layer could not decode, e.g. an mdoc `DeviceResponse` that is no
     * valid CBOR: it is rejected like one that can not be parsed, without credentials.
     */
    fun rejectUndecodable(cause: Throwable): PresentationValidationResult = PresentationValidationResult(
        report = ValidationReport.presentation(
            checks = blockedPresentationChecks(Failed(cause)),
            credentials = emptyList(),
            evaluatedAt = clock.now(),
        ),
        presentation = null,
    )

    /**
     * Reports a protocol response with its [checks], made by the protocol layer, and the reports of the
     * [presentations] it contains, at the time of this validator's clock, see [ValidationReport.protocolResponse].
     */
    fun reportResponse(
        checks: ProtocolResponseChecks,
        presentations: List<ValidationReport>,
    ): ValidationReport = ValidationReport.protocolResponse(checks, presentations, clock.now())

    /** Adds trust and status to a format [evaluation], and reports it. */
    private suspend fun complete(
        evaluation: FormatEvaluation,
        policy: ValidationPolicy,
        timeScope: TimeScope,
    ): CredentialValidationResult {
        val checks = when (evaluation) {
            is WithoutPrerequisites ->
                credentialChecksWithoutPrerequisites(evaluation.parsing, evaluation.issuerSignature)

            is Evaluated -> checks(evaluation, policy, timeScope)
        }
        val report = ValidationReport.credential(checks, policy, timeScope.now)
        val credential = (evaluation as? Evaluated)?.credential
            ?.takeIf { report.decision == ValidationDecision.ACCEPTED }
        return CredentialValidationResult(report, credential)
    }

    private suspend fun checks(
        evaluation: Evaluated,
        policy: ValidationPolicy,
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
        return withoutStatus.copy(status = status(evaluation, withoutStatus, policy, timeScope))
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
        timeScope: TimeScope,
    ): StatusValidation {
        val otherwiseAccepted = withoutStatus.meets(policy.copy(status = StatusPolicy.Skip))
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
