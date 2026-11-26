package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed

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
 * Holder binding of a standalone credential bound to [holderKey], `null` if it is not holder-bound: not applicable
 * unless [this] requires an expected key, blocked without one (holder binding fails closed), otherwise whether
 * [holderKey] is one of the expected keys of [context].
 */
internal fun HolderBindingPolicy.check(
    context: CredentialValidationContext,
    holderKey: CryptoPublicKey?,
): CheckOutcome = when (this) {
    HolderBindingPolicy.None -> NotApplicable
    HolderBindingPolicy.RequireExpectedKey -> {
        val expected = context.allExpectedHolderKeys
        when {
            expected.isEmpty() ->
                Blocked(IllegalStateException("No expected holder key to check the binding against"))
            // Compared cryptographically, as the key decoded from the credential may be encoded unlike the expected one
            holderKey != null && expected.any { it.equalsCryptographically(holderKey) } -> Passed
            else -> Failed(IllegalArgumentException("The credential is not bound to an expected holder key"))
        }
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

/** The timeliness of a credential with this validity period, see [ValidityPeriod.check]. */
internal fun ValidityPeriod.timeliness(timeScope: TimeScope) =
    TimelinessValidation(check(timeScope, "credential"), this)
