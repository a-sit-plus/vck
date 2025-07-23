package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlin.time.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * 4.1.4.  "exp" (Expiration Time) Claim
 *
 *    The "exp" (expiration time) claim identifies the expiration time on
 *    or after which the JWT MUST NOT be accepted for processing.  The
 *    processing of the "exp" claim requires that the current date/time
 *    MUST be before the expiration date/time listed in the "exp" claim.
 *    Implementers MAY provide for some small leeway, usually no more than
 *    a few minutes, to account for clock skew.  Its value MUST be a number
 *    containing a NumericDate value.  Use of this claim is OPTIONAL.
 */
@Serializable
@JvmInline
value class JwtExpirationTimeClaim(val numericDate: NumericDate) {
    val instant: Instant
        get() = numericDate.instant

    fun isInvalid(
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(instant)

    companion object {
        operator fun invoke(instant: Instant) = JwtExpirationTimeClaim(NumericDate(instant))
    }

    data object Specification {
        const val CLAIM_NAME = "exp"
    }
}