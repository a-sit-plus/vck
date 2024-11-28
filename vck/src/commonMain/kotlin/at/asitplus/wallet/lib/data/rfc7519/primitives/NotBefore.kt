package at.asitplus.wallet.lib.data.rfc7519.primitives

import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class NotBefore(private val delegate: NumericDate) {
    val instant: Instant
        get() = delegate.instant

    fun isInvalid(
        isInstantInThePast: (Instant) -> Boolean,
    ) = !isInstantInThePast(instant)
}