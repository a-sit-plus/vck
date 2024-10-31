package at.asitplus.rqes.collection_entries

import at.asitplus.rqes.Hashes
import at.asitplus.rqes.contentEquals
import at.asitplus.rqes.contentHashCode
import at.asitplus.rqes.enums.ConformanceLevelEnum
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.enums.SignedEnvelopeProperty
import at.asitplus.rqes.getHashAlgorithm
import at.asitplus.rqes.getSignAlgorithm
import at.asitplus.rqes.serializers.Asn1EncodableBase64Serializer
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonObject


/**
 * CSC: Class used as part of [SignatureRequestParameters]
 */
@Serializable
data class CscDocumentDigest(
    /**
     * One or more hash values representing one or more SDRs. This
     * parameter SHALL contain the Base64-encoded hash(es) of the
     * documents to be signed.
     * Does not use hashes serializer as it is defined as array of string instead of string.
     */
    @SerialName("hashes")
    val hashes: Hashes,

    /**
     * Hashing algorithm OID used to calculate document(s) hash(es). This
     * parameter MAY be omitted or ignored if the hash algorithm is
     * implicitly specified by the signAlgo algorithm. Only hashing algorithms
     * as strong or stronger than SHA256 SHALL be used
     */
    @SerialName("hashAlgorithmOID")
    val hashAlgorithmOid: ObjectIdentifier? = null,

    /**
     * Requested Signature Format
     */
    @SerialName("signature_format")
    val signatureFormat: SignatureFormat,

    /**
     * Requested conformance level. If omitted its value is "AdES-B-B"
     */
    @SerialName("conformance_level")
    val conformanceLevel: ConformanceLevelEnum? = null,

    /**
     * The OID of the algorithm to use for signing
     */
    @SerialName("signAlgo")
    val signAlgoOid: ObjectIdentifier,

    /**
     * The Base64-encoded DER-encoded ASN.1 signature algorithm parameters if required by
     * the signature algorithm - Necessary for RSASSA-PSS for example
     */
    @SerialName("signAlgoParams")
    @Serializable(with = Asn1EncodableBase64Serializer::class)
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
    val signAlgorithm: SignatureAlgorithm? =
        getSignAlgorithm(signAlgoOid, signAlgoParams)

    @Transient
    val hashAlgorithm: Digest = getHashAlgorithm(hashAlgorithmOid, signAlgorithm)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CscDocumentDigest

        if (!hashes.contentEquals(other.hashes)) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (signatureFormat != other.signatureFormat) return false
        if (conformanceLevel != other.conformanceLevel) return false
        if (signAlgoOid != other.signAlgoOid) return false
        if (signAlgoParams != other.signAlgoParams) return false
        if (signedProps != other.signedProps) return false
        if (signedEnvelopeProperty != other.signedEnvelopeProperty) return false
        if (signAlgorithm != other.signAlgorithm) return false
        if (hashAlgorithm != other.hashAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hashes.contentHashCode()
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + signatureFormat.hashCode()
        result = 31 * result + (conformanceLevel?.hashCode() ?: 0)
        result = 31 * result + signAlgoOid.hashCode()
        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
        result = 31 * result + (signedProps?.hashCode() ?: 0)
        result = 31 * result + (signedEnvelopeProperty?.hashCode() ?: 0)
        result = 31 * result + (signAlgorithm?.hashCode() ?: 0)
        result = 31 * result + hashAlgorithm.hashCode()
        return result
    }
}



