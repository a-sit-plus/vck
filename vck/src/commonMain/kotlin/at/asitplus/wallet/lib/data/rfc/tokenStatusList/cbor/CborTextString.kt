package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cbor

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class CborTextString(val value: String)