package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.iso.IssuerSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlinx.serialization.decodeFromByteArray

/**
 * Evaluates the `IssuerSigned` structure of an ISO mdoc (ISO/IEC 18013-5:2021, 9.3.1 *Inspection procedure for
 * issuer data authentication*): decodes it with its MSO, verifies `issuerAuth`, checks every supplied issuer-signed
 * item against the MSO (see [validateIssuerSignedItems]), holder binding by the MSO device key, and the validity of
 * the MSO. Trust anchors are selected by the MSO `docType`.
 *
 * The semantics include that the `validityInfo` is consistent, that the MSO was signed within the validity of its
 * document signer certificate, and the issuing authority of an mDL (see [validityIsConsistent],
 * [isSignedWithinValidityOf], [issuingAuthorityAgreesWith]); whether it expires within that certificate is recorded
 * only (see [expiresWithin]).
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
    return evaluateIssuerSigned(issuerSigned, signatureCheck, holderBinding, context, timeScope)
}

/** Evaluates a decoded [issuerSigned], e.g. of a `Document` in a presentation, see [evaluateIsoMdoc]. */
internal suspend fun evaluateIssuerSigned(
    issuerSigned: IssuerSigned,
    signatureCheck: SignatureCheck,
    holderBinding: HolderBindingPolicy,
    context: CredentialValidationContext,
    timeScope: TimeScope,
): FormatEvaluation {
    val mso = issuerSigned.issuerAuth.payload
        ?: return FormatEvaluation.WithoutPrerequisites(
            parsing = Failed(IllegalArgumentException("The issuerAuth carries no MSO")),
            issuerSignature = Passed,
        )
    val signature = signatureCheck.verify(issuerSigned.issuerAuth)
    if (signature.outcome != Passed)
        return FormatEvaluation.WithoutPrerequisites(Passed, signature.outcome)
    // Without a certificate, there is no document signer to relate the MSO to, and the issuer is not trusted either
    val documentSigner = signature.certificateChain?.firstOrNull()
    return FormatEvaluation.Evaluated(
        credentialIdentifier = mso.docType,
        certificateChain = signature.certificateChain,
        semantics = semanticsOf(
            expectedIdentifier(context.expectedCredentialIdentifier, listOf(mso.docType)),
            mso.validityIsConsistent(),
            documentSigner?.let { mso.isSignedWithinValidityOf(it, timeScope) } ?: Passed,
            documentSigner?.let { issuerSigned.issuingAuthorityAgreesWith(mso.docType, it) } ?: Passed,
        ),
        disclosedItems = validateIssuerSignedItems(issuerSigned, mso),
        holderBinding = holderBinding.check(context.expectedHolderKey) { key ->
            mso.deviceKeyInfo.deviceKey.toCryptoPublicKey().getOrNull() == key
        },
        timeliness = MdocTimelinessValidator(issuerSigned, timeScope).let { details ->
            CredentialTimelinessValidationSummary.Mdoc(details).toValidation(
                evaluatedAt = timeScope.now,
                notYetValid = listOf(details.msoTimelinessValidationSummary?.mdocNotYetValidError),
                expired = listOf(details.msoTimelinessValidationSummary?.mdocExpiredError),
            )
        },
        status = mso.status?.let { TokenStatusInfo.from(it) },
        credential = ValidatedCredential.IsoMdoc(issuerSigned),
        expiryWithinCertificate = documentSigner?.let { mso.expiresWithin(it) } ?: NotApplicable,
    )
}
