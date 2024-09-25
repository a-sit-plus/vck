package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.CoseKey
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class DeviceKeyInfo(
    @SerialName("deviceKey")
    val deviceKey: CoseKey,
    @SerialName("keyAuthorizations")
    val keyAuthorizations: KeyAuthorization? = null,
    @SerialName("keyInfo")
    val keyInfo: Map<Int, String>? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceKeyInfo>(it)
        }.wrap()
    }
}