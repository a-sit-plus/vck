package at.asitplus.wallet.lib.validation

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlin.time.Instant

/** The [status] of an artifact was determined, but is not accepted by the [StatusPolicy]. */
class TokenStatusException(
    val status: TokenStatus
) : IllegalArgumentException("Token status $status is not accepted")

/**
 * A validity period, from [notBefore] to [notAfter] (either may be absent), does not contain [evaluatedAt], taking
 * the leeway of the [ValidationPolicy] into account.
 */
class TimelinessException(
    message: String,
    val evaluatedAt: Instant,
    val notBefore: Instant?,
    val notAfter: Instant?,
) : IllegalArgumentException(message)
