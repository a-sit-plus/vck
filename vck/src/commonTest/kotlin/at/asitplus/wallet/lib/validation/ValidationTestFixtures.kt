package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

internal val evaluatedAt = Instant.fromEpochSeconds(1_800_000_000)

internal val failure = IllegalStateException("check failed")

internal val requireClaim = StatusPolicy.RequireClaim(TrustPolicy.RequireAuthorizedSigner)

internal val ifPresent = StatusPolicy.ValidateIfPresent(TrustPolicy.RequireAuthorizedSigner)

internal val strictPolicy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = requireClaim,
    timeLeeway = 300.seconds,
    requireTimeliness = true,
)

internal val statusListInfo = StatusListInfo(
    index = 1U,
    uri = UniformResourceIdentifier("https://example.com/statuslist.jwt"),
)

internal val identifierListInfo = IdentifierListInfo(
    identifier = byteArrayOf(0x01),
    uri = UniformResourceIdentifier("https://example.com/identifierlist.cwt"),
)

internal val trusted = TrustValidation(Passed, credentialIdentifier = "urn:eudi:pid:1", source = "PID providers")

internal val passingToken = StatusListTokenChecks(
    retrieval = Passed,
    parsing = Passed,
    signature = Passed,
    signerTrust = trusted,
    subject = Passed,
    timeliness = Passed,
)

internal fun tokenReport(
    checks: StatusListTokenChecks = passingToken,
    signerTrust: TrustPolicy = TrustPolicy.RequireAuthorizedSigner,
) = ValidationReport.statusListToken(checks, signerTrust, evaluatedAt)

internal fun mechanism(
    reference: RevocationListInfo = statusListInfo,
    observed: TokenStatus? = TokenStatus.Valid,
) = StatusMechanismValidation(
    reference = reference,
    token = tokenReport(),
    outcome = if (observed == null) CheckOutcome.Blocked() else Passed,
    observed = observed,
)

internal fun statusOf(vararg mechanisms: StatusMechanismValidation) =
    StatusValidation(Passed, mechanisms.toList(), statusAgreement(mechanisms.toList()))

internal val validStatus = statusOf(mechanism())
