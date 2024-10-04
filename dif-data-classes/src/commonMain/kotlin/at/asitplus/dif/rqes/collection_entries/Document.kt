package at.asitplus.dif.rqes.collection_entries

import at.asitplus.dif.rqes.enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.enums.SignatureFormat
import at.asitplus.dif.rqes.enums.SignedEnvelopeProperty
import at.asitplus.dif.rqes.getSignAlgorithm
import at.asitplus.signum.indispensable.Digest
import at.asitplus.dif.rqes.serializers.Asn1EncodableBase64Serializer
import at.asitplus.dif.rqes.getSignAlgorithm
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
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
    @Serializable(ByteArrayBase64Serializer::class)
    val document: ByteArray,

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
    val signAlgoOid: ObjectIdentifier,

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
) {
    @Transient
    val signAlgorithm: SignatureAlgorithm? = getSignAlgorithm(signAlgoOid, signAlgoParams)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Document

        if (!document.contentEquals(other.document)) return false
        if (signatureFormat != other.signatureFormat) return false
        if (conformanceLevel != other.conformanceLevel) return false
        if (signAlgoOid != other.signAlgoOid) return false
        if (signAlgoParams != other.signAlgoParams) return false
        if (signedProps != other.signedProps) return false
        if (signedEnvelopeProperty != other.signedEnvelopeProperty) return false
        if (signAlgorithm != other.signAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = document.contentHashCode()
        result = 31 * result + signatureFormat.hashCode()
        result = 31 * result + (conformanceLevel?.hashCode() ?: 0)
        result = 31 * result + signAlgoOid.hashCode()
        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
        result = 31 * result + (signedProps?.hashCode() ?: 0)
        result = 31 * result + (signedEnvelopeProperty?.hashCode() ?: 0)
        result = 31 * result + (signAlgorithm?.hashCode() ?: 0)
        return result
    }

}
