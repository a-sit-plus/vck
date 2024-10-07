@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import kotlinx.serialization.*
import kotlinx.serialization.cbor.Cbor

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

    /**
     * Ensures serialization of this structure in [IssuerSigned.issuerAuth]:
     * ```
     * IssuerAuth = COSE_Sign1     ; The payload is MobileSecurityObjectBytes
     * MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
     * ```
     *
     * See ISO/IEC 18013-5:2021, 9.1.2.4 Signing method and structure for MSO
     */
    fun serializeForIssuerAuth() = vckCborSerializer.encodeToByteArray(
            ByteStringWrapperSerializer(serializer()), ByteStringWrapper(this)
        ).wrapInCborTag(24)

    companion object {
        /**
         * Deserializes the structure from the [IssuerSigned.issuerAuth] is deserialized:
         * ```
         * IssuerAuth = COSE_Sign1     ; The payload is MobileSecurityObjectBytes
         * MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
         * ```
         *
         * See ISO/IEC 18013-5:2021, 9.1.2.4 Signing method and structure for MSO
         */
        fun deserializeFromIssuerAuth(it: ByteArray) = kotlin.runCatching {
            Cbor(vckCborSerializer) { verifyValueTags = false }.decodeFromByteArray(
                ByteStringWrapperSerializer(serializer()),
                it.stripCborTag(24)
            ).value
        }.wrap()

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<MobileSecurityObject>(it)
        }.wrap()
    }
}


