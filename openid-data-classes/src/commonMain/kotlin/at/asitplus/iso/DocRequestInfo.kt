package at.asitplus.iso

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
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
    /**
     * The CBOR-encoded registration certificate (WRPRC) of the relying party, which a request to an EUDI Wallet
     * contains (ETSI TS 119 472-2 V1.2.1, ISO/IEC 18013-5-REQ-05 to -07, as adapted by CIR (EU) 2026/1731,
     * Annex XII). The adaptation voids `euWrpRegistrarInfo` (REQ-08 to -11).
     */
    @SerialName("euWrprc")
    @ByteString
    val euWrprc: ByteArray? = null,
    /**
     * The format of the requested document: [DOC_FORMAT_MSO_MDOC] if absent, or [DOC_FORMAT_SD_JWT] for an SD-JWT VC
     * whose `vct` is the requested `docType`, with its claims requested in the namespace [SD_JWT_NAMESPACE] (WG10
     * N2933 v2, "DeviceRequest changes"). Other values use a collision-resistant name.
     */
    @SerialName("docFormat")
    val docFormat: String? = null,
    /**
     * For [DOC_FORMAT_SD_JWT], the SD-JWT claim path each `DataElementIdentifier` of this request stands for, a
     * non-empty array of text strings, unsigned integers, and `null` (WG10 N2933 v2, "DeviceRequest changes").
     */
    @SerialName("dataElementIdentifierMapping")
    val dataElementIdentifierMapping: Map<String, @Serializable(with = SdJwtClaimPathSerializer::class) DCQLClaimsPathPointer>? = null,
) {
    /** Whether this requests an SD-JWT VC, see [docFormat]. */
    val isSdJwt: Boolean
        get() = docFormat == DOC_FORMAT_SD_JWT

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
        if (docFormat != other.docFormat) return false
        if (dataElementIdentifierMapping != other.dataElementIdentifierMapping) return false

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
        result = 31 * result + (docFormat?.hashCode() ?: 0)
        result = 31 * result + (dataElementIdentifierMapping?.hashCode() ?: 0)
        return result
    }

    companion object {
        /** The format of an ISO mdoc, assumed if [docFormat] is absent. */
        const val DOC_FORMAT_MSO_MDOC = "mso_mdoc"

        /** The format of an SD-JWT VC with key binding (WG10 N2933 v2). */
        const val DOC_FORMAT_SD_JWT = "dc+sd-jwt"

        /** The namespace the claims of an SD-JWT VC are requested in, which is not used otherwise (WG10 N2933 v2). */
        const val SD_JWT_NAMESPACE = "_"
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
