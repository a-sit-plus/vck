package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlinx.serialization.decodeFromByteArray

/**
 * Evaluates the `IssuerSigned` structure of an ISO mdoc (ISO/IEC 18013-5:2021, 9.3.1 *Inspection procedure for
 * issuer data authentication*): decodes it with its MSO, verifies `issuerAuth`, checks every supplied issuer-signed
 * item against the MSO (see [validateIssuerSignedItems]), holder binding by the MSO device key, and the validity of
 * the MSO. Trust anchors are selected by the MSO `docType`.
 *
 * Without an MSO nothing can be relied upon, so the credential fails parsing and time is never reported as timely.
 */
internal suspend fun evaluateIsoMdoc(
    input: CredentialValidationInput.IsoMdoc,
    signatureCheck: SignatureCheck,
    holderBinding: HolderBindingPolicy,
    context: CredentialValidationContext,
    timeScope: TimeScope,
): FormatEvaluation {
    val issuerSigned = catching { coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.issuerSignedCbor) }
        .getOrElse { return FormatEvaluation.WithoutPrerequisites(Failed(it), issuerSignature = Passed) }
    val mso = issuerSigned.issuerAuth.payload
        ?: return FormatEvaluation.WithoutPrerequisites(
            parsing = Failed(IllegalArgumentException("The issuerAuth carries no MSO")),
            issuerSignature = Passed,
        )
    val signature = signatureCheck.verify(issuerSigned.issuerAuth)
    if (signature.outcome != Passed)
        return FormatEvaluation.WithoutPrerequisites(Passed, signature.outcome)
    return FormatEvaluation.Evaluated(
        credentialIdentifier = mso.docType,
        certificateChain = signature.certificateChain,
        semantics = expectedIdentifier(context.expectedCredentialIdentifier, listOf(mso.docType)),
        disclosedItems = validateIssuerSignedItems(issuerSigned, mso),
        holderBinding = holderBinding.check(context.expectedHolderKey) { key ->
            mso.deviceKeyInfo.deviceKey.toCryptoPublicKey().getOrNull() == key
        },
        timeliness = MdocTimelinessValidator()(issuerSigned, timeScope).let { details ->
            CredentialTimelinessValidationSummary.Mdoc(details).toValidation(
                evaluatedAt = timeScope.now,
                notYetValid = listOf(details.msoTimelinessValidationSummary?.mdocNotYetValidError),
                expired = listOf(details.msoTimelinessValidationSummary?.mdocExpiredError),
            )
        },
        status = mso.status?.let { TokenStatusInfo.from(it) },
        credential = ValidatedCredential.IsoMdoc(issuerSigned),
    )
}
