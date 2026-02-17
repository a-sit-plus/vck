@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2026 standard: Mdoc request (10.2)
 */
@Serializable
data class DeviceRequest(
    @SerialName("version")
    val version: String,
    @SerialName("docRequests")
    val docRequests: Array<DocRequest>,
    @SerialName("deviceRequestInfo")
    @ValueTags(24U)
    val deviceRequestInfo: ByteStringWrapper<DeviceRequestInfo>? = null,
    @SerialName("readerAuthAll")
    val readerAuthAll: Array<CoseSigned<ByteArray>>? = null,
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceRequest

        if (version != other.version) return false
        if (!docRequests.contentEquals(other.docRequests)) return false
        if (deviceRequestInfo != other.deviceRequestInfo) return false
        if (readerAuthAll != null) {
            if (other.readerAuthAll == null) return false
            if (!readerAuthAll.contentEquals(other.readerAuthAll)) return false
        } else if (other.readerAuthAll != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + docRequests.contentHashCode()
        result = 31 * result + (deviceRequestInfo?.hashCode() ?: 0)
        result = 31 * result + (readerAuthAll?.contentHashCode() ?: 0)
        return result
    }
}

object DeviceRequestBase64UrlSerializer : TransformingSerializerTemplate<DeviceRequest, String>(
    parent = String.serializer(),
    encodeAs = { coseCompliantSerializer.encodeToByteArray(it).encodeToString(Base64UrlStrict) },
    decodeAs = { coseCompliantSerializer.decodeFromByteArray<DeviceRequest>(it.decodeToByteArray(Base64UrlStrict)) }
)
