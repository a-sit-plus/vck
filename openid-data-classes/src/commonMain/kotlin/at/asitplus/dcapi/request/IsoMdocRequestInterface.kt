package at.asitplus.dcapi.request

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed interface IsoMdocRequestInterface {
    @SerialName("deviceRequest")
    val deviceRequest: DeviceRequest

    @SerialName("encryptionInfo")
    val encryptionInfo: EncryptionInfo
}