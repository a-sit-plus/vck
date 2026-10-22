package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

/*
 * The checks key attestations and client (wallet instance) attestations share: both are signed by a wallet provider,
 * and both reference a status list entry the wallet provider maintains (EUDI TS3, 2.4.1).
 */

private const val WALLET_PROVIDERS = "wallet providers"
private const val WALLET_PROVIDER_STATUS = "status list signers of wallet providers"

/**
 * Whether a wallet provider authorized by [anchors] signed with the leaf of [chain]: the signing certificate is an
 * anchor itself, or leads to one through the intermediate certificates of [chain], see
 * [TrustRule.ISSUED_BY_ANCHOR_OR_LISTED].
 */
internal suspend fun walletProviderTrust(
    chain: CertificateChain?,
    anchors: TrustedCertificates?,
    at: Instant,
): TrustValidation = TrustValidation(
    outcome = checkTrust(chain, anchors?.invoke(), at, TrustRule.ISSUED_BY_ANCHOR_OR_LISTED),
    source = WALLET_PROVIDERS,
)

/**
 * The status of a wallet provider's artifact, i.e. the `status` of `key_storage_status` or `client_status` (EUDI
 * TS3, 2.3.1, 2.3.2), resolved only if the artifact is [otherwiseAccepted] (draft-ietf-oauth-status-list-21, 8.3),
 * and signed by an anchor of [statusAnchors].
 */
internal suspend fun walletProviderStatus(
    status: JsonObject?,
    artifact: String,
    otherwiseAccepted: Boolean,
    statusValidator: StatusValidator,
    statusAnchors: TrustedCertificates?,
    policy: ValidationPolicy,
    evaluatedAt: Instant,
): StatusValidation {
    if (policy.status != StatusPolicy.Skip && status != null && !otherwiseAccepted) {
        return StatusValidation(
            claim = Blocked(IllegalStateException("The status of an invalid $artifact is not resolved")),
            agreement = NotApplicable,
        )
    }
    val statusInfo = status?.let {
        catching { joseCompliantSerializer.decodeFromJsonElement(TokenStatusInfo.serializer(), it) }.getOrElse {
            return StatusValidation(claim = Failed(it), agreement = NotApplicable)
        }
    }
    return statusValidator.validate(
        status = statusInfo,
        signerAnchors = StatusSignerAnchors.OfArtifactKind(statusAnchors, WALLET_PROVIDER_STATUS),
        policy = policy.status,
        timeLeeway = policy.timeLeeway,
        evaluatedAt = evaluatedAt,
    )
}
