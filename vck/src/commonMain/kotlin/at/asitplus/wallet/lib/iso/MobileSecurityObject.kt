package at.asitplus.wallet.lib.iso

import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigestList
import at.asitplus.wallet.lib.data.Status
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class MobileSecurityObject(
    @SerialName("version")
    val version: String,
    @SerialName("digestAlgorithm")
    val digestAlgorithm: String,
    @SerialName("valueDigests")
    val valueDigests: Map<String, ValueDigestList>,
    @SerialName("deviceKeyInfo")
    val deviceKeyInfo: DeviceKeyInfo,
    @SerialName("docType")
    val docType: String,
    @SerialName("validityInfo")
    val validityInfo: ValidityInfo,
    @SerialName("status")
    val status: Status? = null,
)