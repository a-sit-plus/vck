package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsContentSemanticsValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import at.asitplus.wallet.lib.data.VcDataModelConstants
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed

/**
 * Evaluates a VC-JWT (W3C VC Data Model 1.1, *JWT decoding*): parses it, verifies the issuer signature, and checks
 * that the JWT claims agree with the credential, holder binding by `sub`, and time.
 *
 * Trust anchors are selected by the signed VC type other than `VerifiableCredential`: with several, only an
 * [CredentialValidationContext.expectedCredentialIdentifier] among them selects one, otherwise the type is ambiguous.
 */
internal suspend fun evaluateVcJwt(
    input: CredentialValidationInput.VcJwt,
    signatureCheck: SignatureCheck,
    holderBinding: HolderBindingPolicy,
    context: CredentialValidationContext,
    timeScope: TimeScope,
): FormatEvaluation {
    val jws = catching { JwsCompactTyped<VerifiableCredentialJws>(input.compact) }.getOrElse {
        return FormatEvaluation.WithoutPrerequisites(Failed(it), issuerSignature = Passed)
    }
    val signature = signatureCheck.verify(jws.jws)
    if (signature.outcome != Passed)
        return FormatEvaluation.WithoutPrerequisites(Passed, signature.outcome)
    val vcJws = jws.payload
    val types = vcJws.vc.type.filter { it != VcDataModelConstants.VERIFIABLE_CREDENTIAL }
    val expected = context.expectedCredentialIdentifier
    return FormatEvaluation.Evaluated(
        credentialIdentifier = expected?.takeIf { it in types } ?: types.singleOrNull(),
        certificateChain = signature.certificateChain,
        semantics = semanticsOf(vcJws.semantics(), expectedIdentifier(expected, types)),
        disclosedItems = emptyList(),
        holderBinding = holderBinding.check(context.expectedHolderKey) { key ->
            vcJws.subject?.let { key.matchesIdentifier(it) } == true
        },
        timeliness = VcJwsTimelinessValidator()(vcJws, timeScope).let { details ->
            CredentialTimelinessValidationSummary.VcJws(details).toValidation(
                evaluatedAt = timeScope.now,
                notYetValid = listOf(details.jwsNotYetValidError, details.credentialNotYetValidError),
                expired = listOf(details.jwsExpiredError, details.credentialExpiredError),
            )
        },
        status = vcJws.vc.credentialStatus?.let { TokenStatusInfo.from(it) },
        credential = ValidatedCredential.VcJwt(vcJws),
    )
}

/** The JWT claims agree with the credential, which contains the type `VerifiableCredential`. */
private fun VerifiableCredentialJws.semantics(): CheckOutcome {
    val summary = VcJwsContentSemanticsValidator()(this)
    if (summary.isSuccess) return Passed
    // Names the inconsistent claims only, never their values
    val inconsistent = listOfNotNull(
        summary.inconsistentIssuerError?.let { "iss" },
        summary.inconsistentIdentifierError?.let { "jti" },
        summary.inconsistentSubjectError?.let { "sub" },
        summary.missingCredentialTypeError?.let { "type" },
        summary.inconsistentNotBeforeTimeError?.let { "nbf" },
        summary.inconsistentExpirationTimeError?.let { "exp" },
    )
    return Failed(IllegalArgumentException("The JWT claims disagree with the credential: $inconsistent"))
}
