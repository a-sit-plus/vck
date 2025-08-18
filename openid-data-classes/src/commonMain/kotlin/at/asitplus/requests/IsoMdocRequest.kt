package at.asitplus.requests

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class IsoMdocRequest(
    @SerialName("deviceRequest")
    val deviceRequest: DeviceRequest,
    @SerialName("encryptionInfo")
    val encryptionInfo: EncryptionInfo,
    @SerialName("credentialId")
    override val credentialId: String,
    @SerialName("callingPackageName")
    val callingPackageName: String,
    @SerialName("callingOrigin")
    val callingOrigin: String
) : DcApiRequest