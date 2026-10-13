package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VcJwsVerificationResultWrapper
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.PresentationValidationResult
import at.asitplus.wallet.lib.validation.StatusValidation
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport

/*
 * The legacy results of verifiers, projected from the one validation of each presentation with a CredentialValidator,
 * so that the deprecated results apply the same rules as the reports.
 */

/**
 * The legacy result of the [validations] of one presentation of a `vp_token`, transported as [compact]: one
 * validation, or one per document of an mdoc `DeviceResponse`, whose accepted documents form one result. A rejected
 * presentation fails with the cause of its first rejecting check under [policy].
 */
internal fun legacyPresentationResult(
    compact: String,
    validations: List<PresentationValidationResult>,
    policy: ValidationPolicy,
): KmmResult<VerifyPresentationResult> = catching {
    val accepted = validations.filter { it.presentation != null }
    if (accepted.isEmpty()) {
        throw validations.firstNotNullOfOrNull { it.rejection(policy) }
            ?: IllegalArgumentException("The presentation contains no document")
    }
    val documents = accepted.mapNotNull { validation ->
        (validation.presentation as? ValidatedPresentation.MdocDocument)?.let { it to validation.report }
    }
    if (documents.isNotEmpty()) {
        VerifyPresentationResult.SuccessIso(documents.map { (presentation, report) -> presentation.parsed(report) })
    } else {
        val validation = accepted.single()
        when (val presentation = validation.presentation!!) {
            is ValidatedPresentation.SdJwt -> presentation.success(compact, validation.report)
            is ValidatedPresentation.VpJwt -> presentation.success(compact, validation.report)
            is ValidatedPresentation.VcJwt -> VerifyPresentationResult.SuccessUnsigned(
                VcJwsVerificationResultWrapper(
                    vcJws = presentation.credential.credential,
                    freshnessSummary = validation.report.children.single().vcJwsFreshness(
                        hasStatusClaim = presentation.credential.credential.vc.credentialStatus != null
                    ),
                )
            )

            is ValidatedPresentation.MdocDocument -> error("Handled above")
        }
    }
}

/** The accepted documents of an ISO/IEC 18013-7 Annex C response, as the legacy result. */
internal fun legacyIsoDocuments(validations: List<PresentationValidationResult>): List<IsoDocumentParsed> =
    validations.mapNotNull { validation ->
        (validation.presentation as? ValidatedPresentation.MdocDocument)?.parsed(validation.report)
    }

/** With the presentation as [SdJwtSigned], i.e. including its key binding JWT, as the legacy result has it. */
private fun ValidatedPresentation.SdJwt.success(
    compact: String,
    report: ValidationReport,
): VerifyPresentationResult.SuccessSdJwt {
    val checks = report.children.single().credentialChecks()
    return VerifyPresentationResult.SuccessSdJwt(
        sdJwtSigned = SdJwtSigned.parseCatching(compact).getOrThrow(),
        verifiableCredentialSdJwt = credential.credential,
        reconstructedJsonObject = credential.reconstructedJsonObject,
        disclosures = credential.disclosures.values,
        freshnessSummary = CredentialFreshnessSummary.SdJwt(
            timelinessValidationSummary = checks.timelinessSummary(),
            tokenStatusValidationResult = checks.status.tokenStatus(credential.credential.statusElement != null),
        ),
    )
}

/** Every credential of an accepted VP is accepted, so all of them are fresh, as far as the policy requires. */
private fun ValidatedPresentation.VpJwt.success(compact: String, report: ValidationReport) =
    VerifyPresentationResult.Success(
        VerifiablePresentationParsed(
            jws = JwsCompactTyped<VerifiablePresentationJws>(compact),
            id = presentation.vp.id,
            type = presentation.vp.type,
            freshVerifiableCredentials = credentials.zip(report.children).map { (credential, credentialReport) ->
                VcJwsVerificationResultWrapper(
                    vcJws = credential.credential,
                    freshnessSummary = credentialReport.vcJwsFreshness(
                        hasStatusClaim = credential.credential.vc.credentialStatus != null
                    ),
                )
            },
        )
    )

private fun ValidatedPresentation.MdocDocument.parsed(report: ValidationReport): IsoDocumentParsed {
    val checks = report.children.single().credentialChecks()
    val mso = credential.issuerSigned.issuerAuth.payload
        ?: throw IllegalStateException("An accepted document has a mobile security object")
    return IsoDocumentParsed(
        document = document,
        mso = mso,
        // Every item of an accepted document matches its digest
        validItems = credential.issuerSigned.namespaces?.values?.flatMap { items -> items.entries.map { it.value } }
            .orEmpty(),
        freshnessSummary = CredentialFreshnessSummary.Mdoc(
            timelinessValidationSummary = checks.timelinessSummary(),
            tokenStatusValidationResult = checks.status.tokenStatus(mso.status != null),
        ),
        documentErrors = document.errors.orEmpty(),
    )
}

private fun ValidationReport.vcJwsFreshness(hasStatusClaim: Boolean): CredentialFreshnessSummary.VcJws {
    val checks = credentialChecks()
    return CredentialFreshnessSummary.VcJws(
        timelinessValidationSummary = checks.timelinessSummary(),
        tokenStatusValidationResult = checks.status.tokenStatus(hasStatusClaim),
    )
}

private fun ValidationReport.credentialChecks() = checks as CredentialChecks

private inline fun <reified T : CredentialTimelinessValidationSummary> CredentialChecks.timelinessSummary(): T =
    timeliness.details as? T ?: throw IllegalStateException("The timeliness of an accepted credential is evaluated")

/**
 * The status as the legacy validators reported it: [TokenStatusValidationResult.Valid] with the observed status if
 * every mechanism verified an accepted one, or without one for a credential without a status; otherwise
 * [TokenStatusValidationResult.Invalid] with a verified status that is not accepted, or
 * [TokenStatusValidationResult.Rejected], e.g. if the policy does not resolve the status.
 */
private fun StatusValidation.tokenStatus(hasStatusClaim: Boolean): TokenStatusValidationResult {
    if (!hasStatusClaim) return TokenStatusValidationResult.Valid(null)
    if (claim != CheckOutcome.Passed || mechanisms.isEmpty()) {
        return TokenStatusValidationResult.Rejected(
            claim.cause() ?: IllegalStateException("The status has not been validated")
        )
    }
    mechanisms.firstOrNull { it.outcome != CheckOutcome.Passed && it.observed != null }?.let {
        return TokenStatusValidationResult.Invalid(it.observed!!)
    }
    (mechanisms.map { it.outcome } + agreement).firstOrNull { it != CheckOutcome.Passed }?.let {
        return TokenStatusValidationResult.Rejected(
            it.cause() ?: IllegalStateException("The status could not be validated")
        )
    }
    return TokenStatusValidationResult.Valid(mechanisms.first().observed)
}

private fun CheckOutcome.cause(): Throwable? = when (this) {
    is CheckOutcome.Failed -> throwable
    is CheckOutcome.Blocked -> cause
    else -> null
}
