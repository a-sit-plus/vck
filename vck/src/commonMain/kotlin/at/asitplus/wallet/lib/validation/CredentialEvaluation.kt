package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.common.EntityExpiredError
import at.asitplus.wallet.lib.agent.validation.common.EntityNotYetValidError
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.time.Instant

/**
 * What the format-specific part of credential validation found, before trust and status are evaluated.
 */
internal sealed interface FormatEvaluation {

    /** Parsing or the issuer signature did not pass, so no claim of the credential can be relied upon. */
    data class WithoutPrerequisites(
        val parsing: CheckOutcome,
        val issuerSignature: CheckOutcome,
    ) : FormatEvaluation

    data class Evaluated(
        /** The signed identifier trust anchors are selected for, `null` if ambiguous. */
        val credentialIdentifier: String?,
        /** The certificate chain of the issuer signature, for the trust check. */
        val certificateChain: CertificateChain?,
        val semantics: CheckOutcome,
        val disclosedItems: List<DisclosedItemValidation>,
        val holderBinding: CheckOutcome,
        val timeliness: TimelinessValidation,
        /** The status claim, `null` if the credential has none. */
        val status: TokenStatusInfo?,
        val credential: ValidatedCredential,
    ) : FormatEvaluation
}

/**
 * Holder binding of a standalone credential: not applicable unless [this] requires the [expected] key, blocked
 * without an expected key, otherwise whether [isBoundTo] the expected key.
 */
internal inline fun HolderBindingPolicy.check(
    expected: CryptoPublicKey?,
    isBoundTo: (CryptoPublicKey) -> Boolean,
): CheckOutcome = when (this) {
    HolderBindingPolicy.None -> NotApplicable
    HolderBindingPolicy.RequireExpectedKey -> when {
        expected == null -> Blocked(IllegalStateException("No expected holder key to check the binding against"))
        isBoundTo(expected) -> Passed
        else -> Failed(IllegalArgumentException("The credential is not bound to the expected holder key"))
    }
}

/**
 * Failed if [expected] is given and the signed [identifiers] do not contain it: the context constrains the signed type,
 * it never replaces it.
 */
internal fun expectedIdentifier(expected: String?, identifiers: Collection<String>): CheckOutcome =
    if (expected == null || expected in identifiers) Passed
    else Failed(IllegalArgumentException("The credential is not of the expected type $expected"))

/** Combines semantic checks: the first failure, otherwise passed. */
internal fun semanticsOf(vararg outcomes: CheckOutcome): CheckOutcome =
    outcomes.firstOrNull { it != Passed } ?: Passed

/**
 * The outcome of the format's timeliness validators: failed with a [TimelinessException] carrying the first violated
 * bound if the credential is expired or not yet valid.
 */
internal fun CredentialTimelinessValidationSummary.toValidation(
    evaluatedAt: Instant,
    notYetValid: List<EntityNotYetValidError?>,
    expired: List<EntityExpiredError?>,
): TimelinessValidation {
    val notBefore = notYetValid.firstNotNullOfOrNull { it?.notBeforeTime }
    val notAfter = expired.firstNotNullOfOrNull { it?.expirationTime }
    val outcome = when {
        isTimely -> Passed
        notBefore != null ->
            Failed(TimelinessException("The credential is not yet valid", evaluatedAt, notBefore, notAfter = null))
        else -> Failed(TimelinessException("The credential is expired", evaluatedAt, null, notAfter))
    }
    return TimelinessValidation(outcome, this)
}
