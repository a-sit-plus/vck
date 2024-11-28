package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Duration

@Serializable(with = TimeToLiveSerializer::class)
interface TimeToLive {
    val duration: Duration
}