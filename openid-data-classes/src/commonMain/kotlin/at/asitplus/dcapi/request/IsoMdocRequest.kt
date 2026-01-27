package at.asitplus.dcapi.request

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestBase64UrlSerializer
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionInfoBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class IsoMdocRequest(
    @SerialName("deviceRequest")
    @Serializable(with = DeviceRequestBase64UrlSerializer::class)
    val deviceRequest: DeviceRequest,
    @SerialName("encryptionInfo")
    @Serializable(with = EncryptionInfoBase64UrlSerializer::class)
    val encryptionInfo: EncryptionInfo,
) {
    @Deprecated("Removed", ReplaceWith("DCAPIWalletRequest.IsoMdoc()"), DeprecationLevel.ERROR)
    constructor(
        deviceRequest: DeviceRequest,
        encryptionInfo: EncryptionInfo,
        credentialId: String,
        callingPackageName: String,
        callingOrigin: String,
    ) : this(
        deviceRequest = deviceRequest,
        encryptionInfo = encryptionInfo
    )

    @Deprecated("Removed", ReplaceWith("DCAPIWalletRequest.IsoMdoc"), DeprecationLevel.ERROR)
    val callingOrigin: String = ""
}
