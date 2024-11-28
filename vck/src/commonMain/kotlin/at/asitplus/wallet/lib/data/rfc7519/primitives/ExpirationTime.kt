package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.wallet.lib.data.rfc8392.primitives.NumericDate
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ExpirationTime(private val delegate: NumericDate) {
    val instant: Instant
        get() = delegate.instant

    fun isInvalid(
        isInstantInThePast: (Instant) -> Boolean,
    ) = isInstantInThePast(instant)

    companion object {
        operator fun invoke(instant: Instant) = ExpirationTime(NumericDate(instant))
    }
}
