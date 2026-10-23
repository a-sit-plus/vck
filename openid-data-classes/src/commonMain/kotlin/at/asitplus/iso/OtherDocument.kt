package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

/**
 * A document of another format than an mdoc in a [DeviceResponse] (WG10 N2933 v2, "DeviceResponse changes", whose
 * details are still to be decided): for [DocRequestInfo.DOC_FORMAT_SD_JWT], [data] is the compact serialization of
 * an SD-JWT with key binding, compressed with DEFLATE (RFC 1951) in the ZLIB format (RFC 1950), as for a status list.
 */
@Serializable
data class OtherDocument(
    @SerialName("docFormat")
    val docFormat: String,
    @SerialName("data")
    @ByteString
    val data: ByteArray,
    /** The indices of the `DocRequest`s in the `docRequests` of the request this document answers, from 0. */
    @SerialName("docRequestIds")
    val docRequestIds: List<UInt>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as OtherDocument

        if (docFormat != other.docFormat) return false
        if (!data.contentEquals(other.data)) return false
        return docRequestIds == other.docRequestIds
    }

    override fun hashCode(): Int {
        var result = docFormat.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + docRequestIds.hashCode()
        return result
    }
}
