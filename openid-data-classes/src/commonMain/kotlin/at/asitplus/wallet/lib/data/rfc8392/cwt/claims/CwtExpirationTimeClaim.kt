package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlin.time.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.4.  exp (Expiration Time) Claim
 *
 *    The "exp" (expiration time) claim has the same meaning and processing
 *    rules as the "exp" claim defined in Section 4.1.4 of [RFC7519],
 *    except that the value is a NumericDate, as defined in Section 2 of
 *    this specification.  The Claim Key 4 is used to identify this claim.
 */
@Serializable
@JvmInline
value class CwtExpirationTimeClaim(val value: NumericDate) {
    val instant: Instant
        get() = value.instant

    fun isInvalid(
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(instant)

    companion object {
        operator fun invoke(instant: Instant) = CwtExpirationTimeClaim(NumericDate(instant))
    }

    data object Specification {
        const val CLAIM_NAME = "exp"
        const val CLAIM_KEY = 4L
    }
}
