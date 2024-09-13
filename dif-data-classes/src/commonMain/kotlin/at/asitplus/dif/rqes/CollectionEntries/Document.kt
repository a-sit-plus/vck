package at.asitplus.dif.rqes.CollectionEntries

import at.asitplus.dif.rqes.Enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC: Class used as part of [SignatureRequestParameters]
 */
@Serializable
data class Document(
    /**
     * base64-encoded document content to be signed, testcases weird so for now string
     */
    @SerialName("document")
//    @Serializable(ByteArrayBase64Serializer::class)
    val document: String,

    /**
     * Requested Signature Format
     */
    @SerialName("signature_format")
    val signatureFormat: SignatureFormat,

    /**
     * Requested conformance level. If omitted its value is "Ades-B-B"
     */
    @EncodeDefault
    @SerialName("conformance_level")
    val conformanceLevel: ConformanceLevelEnum = ConformanceLevelEnum.ADESBB,

    /**
     * The OID of the algorithm to use for signing
     */
    @SerialName("signAlgo")
    val signAlgo: ObjectIdentifier,

    /**
     * TODO: Serializer
     * The Base64-encoded DER-encoded ASN.1 signature parameters
     */
    @SerialName("signAlgoParams")
    val signAlgoParams: String? = null,

    /**
     * TODO: CSC P. 80
     */
    @SerialName("signed_props")
    val signedProps: List<String>? = null,


    @EncodeDefault
    @SerialName("signed_envelope_property")
    val signedEnvelopeProperty: SignedEnvelopeProperty = SignedEnvelopeProperty.defaultProperty(signatureFormat),
)
//{
//    override fun equals(other: Any?): Boolean {
//        if (this === other) return true
//        if (other == null || this::class != other::class) return false
//
//        other as Document
//
//        if (!document.contentEquals(other.document)) return false
//        if (signatureFormat != other.signatureFormat) return false
//        if (conformanceLevel != other.conformanceLevel) return false
//        if (signAlgo != other.signAlgo) return false
//        if (signAlgoParams != other.signAlgoParams) return false
//        if (signedProps != other.signedProps) return false
//
//        return true
//    }
//
//    override fun hashCode(): Int {
//        var result = document.contentHashCode()
//        result = 31 * result + signatureFormat.hashCode()
//        result = 31 * result + conformanceLevel.hashCode()
//        result = 31 * result + signAlgo.hashCode()
//        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
//        result = 31 * result + (signedProps?.hashCode() ?: 0)
//        return result
//    }
//}