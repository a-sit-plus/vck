package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.ValueTags


/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Additional document request info (10.2.4)
 *
 * Fails for an empty [alternativeDataElements] or [issuerIdentifiers], which the CDDL of 10.2.4 does not allow
 * (`[+ AlternativeDataElementsSet]`, `[+IssuerIdentifier]`). An instance without any value is not rejected, although
 * "If present, DocRequestInfo shall contain at least one key-value pair": it is also what decoding one that contains
 * only application-specific extensions (`* tstr => Ext`) results in.
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
    /** `EncryptionParametersBytes = #6.24(bstr .cbor EncryptionParameters)` (ISO/IEC DIS 18013-5:2026, 10.2.4). */
    @SerialName("docResponseEncryption")
    @Serializable(with = ReserializableByteStringSerializer::class)
    @ValueTags(24U)
    val docResponseEncryption: ByteStringWrapper<EncryptionParameters>? = null,
    /**
     * The CBOR-encoded registration certificate (WRPRC) of the relying party, which a request to an EUDI Wallet
     * contains (ETSI TS 119 472-2 V1.2.1, ISO/IEC 18013-5-REQ-05 to -07, as adapted by CIR (EU) 2026/1731,
     * Annex XII). The adaptation voids `euWrpRegistrarInfo` (REQ-08 to -11).
     */
    @SerialName("euWrprc")
    @ByteString
    val euWrprc: ByteArray? = null,
) {
    init {
        require(alternativeDataElements == null || alternativeDataElements.isNotEmpty()) {
            "alternativeDataElements must not be empty if present"
        }
        require(issuerIdentifiers == null || issuerIdentifiers.isNotEmpty()) {
            "issuerIdentifiers must not be empty if present"
        }
    }

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
        if (euWrprc != null && other.euWrprc != null) {
            if (!euWrprc.contentEquals(other.euWrprc)) return false
        } else if (euWrprc != other.euWrprc) return false

        return true
    }

    override fun hashCode(): Int {
        var result = alternativeDataElements?.hashCode() ?: 0
        result = 31 * result + (uniqueDocSetRequired?.hashCode() ?: 0)
        result = 31 * result + (issuerIdentifiers?.fold(1) { acc, arr -> 31 * acc + arr.contentHashCode() } ?: 0)
        result = 31 * result + (maximumResponseSize?.hashCode() ?: 0)
        result = 31 * result + (zkRequest?.hashCode() ?: 0)
        result = 31 * result + (docResponseEncryption?.hashCode() ?: 0)
        result = 31 * result + (euWrprc?.contentHashCode() ?: 0)
        return result
    }
}

/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Additional document request info (10.2.4)
 *
 * Instead of [requestedElement], "all of the data elements of one of the AlternativeElementSet has to be returned",
 * in the order of preference of [alternativeElementSets]. Fails for an empty [alternativeElementSets] or an empty set
 * in it (`"alternativeElementSets": [+AlternativeElementSet]`, `AlternativeElementSet = [+ ElementReference]`).
 */
@Serializable
data class AlternativeDataElementsSet(
    @SerialName("requestedElement")
    val requestedElement: ElementReference,
    @SerialName("alternativeElementSets")
    val alternativeElementSets: List<List<ElementReference>>,
) {
    init {
        require(alternativeElementSets.isNotEmpty()) { "No alternative element set for $requestedElement" }
        require(alternativeElementSets.none { it.isEmpty() }) {
            "An alternative element set for $requestedElement is empty"
        }
    }
}


/**
 * Part of the ISO/IEC DIS 18013-5:2026 standard: Additional document request info (10.2.4),
 * `ElementReference = [NameSpace, DataElementIdentifier]`
 */
@Serializable
@CborArray
data class ElementReference(
    val namespace: String,
    val dataElementIdentifier: String,
) {
    /**
     * Serializes the reference as the array `[namespace, dataElementIdentifier]` in every format, as its CDDL defines
     * it (ISO/IEC DIS 18013-5:2026, 10.2.4), also in JSON, where its default serializer encodes an object.
     */
    object ArraySerializer : KSerializer<ElementReference> by TransformingSerializerTemplate(
        parent = ListSerializer(String.serializer()),
        encodeAs = { listOf(it.namespace, it.dataElementIdentifier) },
        decodeAs = {
            require(it.size == 2) { "An ElementReference has a name space and a data element identifier: $it" }
            ElementReference(it[0], it[1])
        },
        serialName = "at.asitplus.iso.ElementReference.Array",
    )
}
