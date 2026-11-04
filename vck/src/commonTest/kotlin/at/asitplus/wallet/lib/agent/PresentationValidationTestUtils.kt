package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceResponse
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.PresentationContext
import at.asitplus.wallet.lib.validation.PresentationValidationInput
import at.asitplus.wallet.lib.validation.PresentationValidationResult
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * The policy for tests whose issuers are on no trust list: signatures, holder binding, and time are validated, but
 * issuers need not be authorized, and the status is not resolved.
 */
internal val integrityOnlyPolicy = ValidationPolicy(
    trust = TrustPolicy.IntegrityOnly,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

/** [integrityOnlyPolicy], resolving the status of credentials that advertise one, from signers on no trust list. */
internal val statusCheckingPolicy = integrityOnlyPolicy.copy(
    status = StatusPolicy.ValidateIfPresent(signerTrust = TrustPolicy.IntegrityOnly),
)

/** Resolves the status list tokens of [statusListIssuer], as a JWT or a CWT at random. */
internal fun randomCwtOrJwtResolver(statusListIssuer: StatusListAgent) = StatusListTokenResolver {
    if (Random.nextBoolean()) StatusListJwt(
        statusListIssuer.issueStatusListJwt(),
        resolvedAt = Clock.System.now(),
    ) else StatusListCwt(
        statusListIssuer.issueStatusListCwt(),
        resolvedAt = Clock.System.now(),
    )
}

/** A validator of credentials from issuers on no trust list, resolving their status from [statusListIssuer]. */
internal fun statusCheckingValidator(statusListIssuer: StatusListAgent) = CredentialValidator(
    statusValidator = StatusValidator(randomCwtOrJwtResolver(statusListIssuer)),
)

/**
 * Validates [presentation] as received by a verifier in [context], under [policy]: one result, or one per document
 * of a device response, which is transported encoded, as the protocol layer would.
 */
internal suspend fun CredentialValidator.validatePresentation(
    presentation: CreatePresentationResult,
    context: PresentationContext,
    policy: ValidationPolicy = integrityOnlyPolicy,
): List<PresentationValidationResult> = when (presentation) {
    is CreatePresentationResult.VpJws -> listOf(PresentationValidationInput.VpJwt(presentation.serialized))
    is CreatePresentationResult.VcJws -> listOf(PresentationValidationInput.VcJwt(presentation.serialized))
    is CreatePresentationResult.SdJwt -> listOf(PresentationValidationInput.SdJwt(presentation.serialized))
    is CreatePresentationResult.DeviceResponse -> coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(
        coseCompliantSerializer.encodeToByteArray(presentation.deviceResponse)
    ).documents.orEmpty().map { PresentationValidationInput.MdocDocument(it) }
}.map { validate(it, context, policy) }

/** The accepted presentation, failing with the cause of the first rejecting check otherwise. */
internal fun PresentationValidationResult.acceptedOrThrow(): ValidatedPresentation =
    presentation ?: throw rejection() ?: IllegalStateException("Presentation rejected without a cause")

/** The status the single credential of this presentation has been found to have, if it was resolved. */
internal val PresentationValidationResult.observedStatus: TokenStatus?
    get() = report.children.shouldBeSingleton().first().checks.shouldBeInstanceOf<CredentialChecks>()
        .status.mechanisms.shouldBeSingleton().first().observed
