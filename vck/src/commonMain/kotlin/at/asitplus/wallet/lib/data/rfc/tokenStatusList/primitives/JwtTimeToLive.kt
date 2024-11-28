package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Duration

@Serializable(with = JwtTimeToLiveInlineSerializer::class)
@JvmInline
value class JwtTimeToLive(private val value: PositiveDuration) : TimeToLive {
    override val duration: Duration
        get() = value.value
}