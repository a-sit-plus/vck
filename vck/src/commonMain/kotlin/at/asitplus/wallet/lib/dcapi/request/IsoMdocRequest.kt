package at.asitplus.wallet.lib.dcapi.request

import at.asitplus.catching
import at.asitplus.dcapi.request.DCAPIRequest
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.DeviceRequest
import at.asitplus.wallet.lib.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class IsoMdocRequest(
    @SerialName("deviceRequest")
    val deviceRequest: DeviceRequest,
    @SerialName("encryptionInfo")
    val encryptionInfo: EncryptionInfo,
    @SerialName("credentialId")
    val credentialId: String,
    @SerialName("callingPackageName")
    val callingPackageName: String,
    @SerialName("callingOrigin")
    val callingOrigin: String
) : DCAPIRequest() {

    override fun serialize(): String = vckJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String) =
            catching { vckJsonSerializer.decodeFromString<IsoMdocRequest>(input) }
    }
}