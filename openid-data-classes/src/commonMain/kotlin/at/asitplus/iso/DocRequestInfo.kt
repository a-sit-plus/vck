package at.asitplus.iso

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional document request info (10.2.4)
 */
@Serializable
data class DocRequestInfo(
    @SerialName("alternativeDataElements")
    val alternativeDataElements: List<AlternativeDataElementsSet>? = null,
    @SerialName("issuerIdentifiers")
    @ByteString
    val issuerIdentifiers: List<ByteArray>? = null,
    @SerialName("uniqueDocSetRequired")
    val uniqueDocSetRequired: Boolean? = null,
    @SerialName("maximumResponseSize")
    val maximumResponseSize: UInt? = null,
    @SerialName("zkRequest")
    val zkRequest: ZkRequest? = null,
    @SerialName("docResponseEncryption")
    val docResponseEncryption: EncryptionParameters? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DocRequestInfo

        if (alternativeDataElements != other.alternativeDataElements) return false
        if (uniqueDocSetRequired != other.uniqueDocSetRequired) return false
        if (issuerIdentifiers != null && other.issuerIdentifiers != null) {
            if (issuerIdentifiers.size != other.issuerIdentifiers.size) return false
            if (!issuerIdentifiers.zip(other.issuerIdentifiers).all {
                (a, b) -> a.contentEquals(b)
            }) return false
        } else if (issuerIdentifiers != other.issuerIdentifiers) return false

        if (maximumResponseSize != other.maximumResponseSize) return false
        if (zkRequest != other.zkRequest) return false
        if (docResponseEncryption != other.docResponseEncryption) return false

        return true
    }

    override fun hashCode(): Int {
        var result = alternativeDataElements?.hashCode() ?: 0
        result = 31 * result + (uniqueDocSetRequired?.hashCode() ?: 0)
        result = 31 * result + (issuerIdentifiers?.fold(1) { acc, arr -> 31 * acc + arr.contentHashCode() } ?: 0)
        result = 31 * result + (maximumResponseSize?.hashCode() ?: 0)
        result = 31 * result + (zkRequest?.hashCode() ?: 0)
        result = 31 * result + (docResponseEncryption?.hashCode() ?: 0)
        return result
    }
}

/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional document request info (10.2.4)
 */
@Serializable
data class AlternativeDataElementsSet(
    @SerialName("requestedElement")
    val requestedElement: ElementReference,
    @SerialName("alternativeElementSets")
    val alternativeElementSets: List<List<ElementReference>>,
)


/**
 * Part of the ISO/IEC 18013-5:2026 standard: Additional document request info (10.2.4)
 */
@Serializable
@CborArray
data class ElementReference(
    val namespace: String,
    val dataElementIdentifier: String,
)
