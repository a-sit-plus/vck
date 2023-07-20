@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.cbor.CoseKey
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

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
    // TODO equality checks?
    val valueDigests: Map<String, Map<UInt, ByteArray>>,
    @SerialName("deviceKeyInfo")
    val deviceKeyInfo: DeviceKeyInfo,
    @SerialName("docType")
    val docType: String,
    @SerialName("validityInfo")
    val validityInfo: ValidityInfo,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<MobileSecurityObject>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class DeviceKeyInfo(
    @SerialName("deviceKey")
    val deviceKey: CoseKey,
    @SerialName("keyAuthorizations")
    val keyAuthorizations: KeyAuthorization? = null,
    @SerialName("keyInfo")
    val keyInfo: Map<Int, String>? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<DeviceKeyInfo>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class KeyAuthorization(
    @SerialName("nameSpaces")
    val namespaces: Array<String>? = null,
    @SerialName("dataElements")
    val dataElements: Map<String, Array<String>>? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyAuthorization

        if (namespaces != null) {
            if (other.namespaces == null) return false
            if (!namespaces.contentEquals(other.namespaces)) return false
        } else if (other.namespaces != null) return false
        return dataElements == other.dataElements
    }

    override fun hashCode(): Int {
        var result = namespaces?.contentHashCode() ?: 0
        result = 31 * result + (dataElements?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<KeyAuthorization>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class ValidityInfo(
    @SerialName("signed")
    val signed: Instant,
    @SerialName("validFrom")
    val validFrom: Instant,
    @SerialName("validUntil")
    val validUntil: Instant,
    @SerialName("expectedUpdate")
    val expectedUpdate: Instant? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<ValidityInfo>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}
