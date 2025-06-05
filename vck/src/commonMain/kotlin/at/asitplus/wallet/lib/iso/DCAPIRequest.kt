package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
data class DCAPIRequest(
    @SerialName("deviceRequest")
    val deviceRequest: DeviceRequest,
    @SerialName("encryptionInfo")
    val encryptionInfo: EncryptionInfo
) {

    fun serialize() = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = runCatching {
            vckJsonSerializer.decodeFromString<DCAPIRequest>(it)
        }.wrap()
    }
}