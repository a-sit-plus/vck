@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.github.z4kn4fein.semver.Version
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
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Mdoc request (10.2)
 *
 * Fails for what the CDDL of 10.2.2 does not allow: no [docRequests] (`"docRequests" : [+ DocRequest]`), an empty
 * [readerAuthAll] (`? "readerAuthAll" : [+ReaderAuthAll]`), a [deviceRequestInfo] or [readerAuthAll] in a request of a
 * version below 1.1 (the version "shall be “1.0” if deviceRequestInfo and readerAuthAll is not present and “1.1” if one
 * of them is present"), and a use case referencing a document request that does not exist (a DocRequestID "references
 * the DocRequests in the docRequests array, identified by its position starting from 0", 10.2.5).
 *
 * Only that direction of the version rule is enforced: a request of a version above 1.0 without [deviceRequestInfo]
 * and [readerAuthAll] is accepted, as it is processed the same, and rejecting it, e.g. from a reader of a later
 * version, would only hurt interoperability.
 */
@Serializable
data class DeviceRequest(
    @SerialName("version")
    @Serializable(with = IsoVersionSerializer::class)
    val parsedVersion: Version,
    @SerialName("docRequests")
    val docRequests: Array<DocRequest>,
    /**
     * Additional information on the requested documents, e.g. which combinations of them satisfy the request
     * (ISO/IEC DIS 18013-5:2026, 10.2.5). Requires version 1.1.
     */
    @SerialName("deviceRequestInfo")
    @Serializable(with = ReserializableByteStringSerializer::class)
    @ValueTags(24U)
    val deviceRequestInfo: ByteStringWrapper<DeviceRequestInfo>? = null,
    /** Authenticates every document request and [deviceRequestInfo] (ISO/IEC DIS 18013-5:2026, 12.5.4). */
    @SerialName("readerAuthAll")
    val readerAuthAll: Array<CoseSigned<ByteArray>>? = null,
) {
    init {
        require(docRequests.isNotEmpty()) { "A DeviceRequest requests at least one document" }
        require(readerAuthAll == null || readerAuthAll.isNotEmpty()) { "readerAuthAll must not be empty if present" }
        require(
            (deviceRequestInfo == null && readerAuthAll == null) ||
                    parsedVersion >= IsoConstants.VERSION_1_1
        ) {
            "deviceRequestInfo and readerAuthAll require version ${IsoConstants.VERSION_1_1}, " +
                    "but the version is $parsedVersion"
        }
        val documentRequestIds = deviceRequestInfo?.value?.useCases.orEmpty()
            .flatMap { it.documentSets.flatten() }
        val missing = documentRequestIds.filter { it >= docRequests.size.toUInt() }.distinct()
        require(missing.isEmpty()) {
            "Use cases reference the document requests $missing, but there are ${docRequests.size}"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DeviceRequest

        if (parsedVersion != other.parsedVersion) return false
        if (!docRequests.contentEquals(other.docRequests)) return false
        if (deviceRequestInfo != other.deviceRequestInfo) return false
        if (readerAuthAll != null) {
            if (other.readerAuthAll == null) return false
            if (!readerAuthAll.contentEquals(other.readerAuthAll)) return false
        } else if (other.readerAuthAll != null) return false
        return true
    }

    override fun hashCode(): Int {
        var result = parsedVersion.hashCode()
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
