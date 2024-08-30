@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import kotlinx.serialization.*

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
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    fun serializeForIssuerAuth() = vckCborSerializer.encodeToByteArray(
        ByteStringWrapperSerializer<MobileSecurityObject>(serializer()), ByteStringWrapper(this)
    ).wrapInCborTag(24)

    companion object {
        fun deserializeFromIssuerAuth(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray(
                ByteStringWrapperSerializer<MobileSecurityObject>(serializer()),
                it.stripCborTag(24)
            ).value
        }.wrap()

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<MobileSecurityObject>(it)
        }.wrap()
    }
}


