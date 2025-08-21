package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseMac
import at.asitplus.signum.indispensable.cosef.CoseSigned
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@Serializable
data class DeviceAuth(
    @SerialName("deviceSignature")
    val deviceSignature: CoseSigned<ByteArray>? = null,
    @SerialName("deviceMac")
    val deviceMac: CoseMac<ByteArray>? = null, // TODO is COSE_Mac0
)