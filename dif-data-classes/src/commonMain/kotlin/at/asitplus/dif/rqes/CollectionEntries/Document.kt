package at.asitplus.dif.rqes.CollectionEntries

import at.asitplus.dif.rqes.Enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignedEnvelopeProperty
import at.asitplus.dif.rqes.Serializer.Asn1EncodableBase64Serializer
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

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
    @SerialName("conformance_level")
    val conformanceLevel: ConformanceLevelEnum? = null,

    /**
     * The OID of the algorithm to use for signing
     */
    @SerialName("signAlgo")
    val signAlgo: ObjectIdentifier,

    /**
     * The Base64-encoded DER-encoded ASN.1 signature parameters
     */
    @SerialName("signAlgoParams")
    @Serializable(Asn1EncodableBase64Serializer::class)
    val signAlgoParams: Asn1Element? = null,

    /**
     * Defined in CSC v2.0.0.2 P. 81
     * Defines a second way to encode all attributes, none of which are necessary
     * Will be ignored until use-case arises
     */
    @SerialName("signed_props")
    val signedProps: List<JsonObject>? = null,

    /**
     * if omitted/null it is assumed to have value
     * `SignedEnvelopeProperty.defaultProperty(signatureFormat)`
     */
    @SerialName("signed_envelope_property")
    val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
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