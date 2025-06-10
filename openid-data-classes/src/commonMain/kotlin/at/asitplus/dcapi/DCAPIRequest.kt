package at.asitplus.dcapi

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.EncryptionInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
// TODO Needed? Duplicate?
data class DCAPIRequest(
    @SerialName("deviceRequest")
    val deviceRequest: DeviceRequest,
    @SerialName("encryptionInfo")
    val encryptionInfo: EncryptionInfo,
)