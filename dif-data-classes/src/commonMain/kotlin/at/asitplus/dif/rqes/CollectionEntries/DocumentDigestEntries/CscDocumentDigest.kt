package at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries

import at.asitplus.dif.rqes.Enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignedEnvelopeProperty
import at.asitplus.dif.rqes.Hashes
import at.asitplus.dif.rqes.contentEquals
import at.asitplus.dif.rqes.contentHashCode
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import io.ktor.util.reflect.*
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC: Class used as part of [SignatureRequestParameters]
 * TODO finish member description
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
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CscDocumentDigest

        if (!hashes.contentEquals(other.hashes)) return false
        if (hashAlgorithmOid != other.hashAlgorithmOid) return false
        if (signatureFormat != other.signatureFormat) return false
        if (conformanceLevel != other.conformanceLevel) return false
        if (signAlgo != other.signAlgo) return false
        if (signAlgoParams != other.signAlgoParams) return false
        if (signedProps != other.signedProps) return false
        if (signedEnvelopeProperty != other.signedEnvelopeProperty) return false

        return true
    }

    override fun hashCode(): Int {
        var result = hashes.contentHashCode()
        result = 31 * result + (hashAlgorithmOid?.hashCode() ?: 0)
        result = 31 * result + signatureFormat.hashCode()
        result = 31 * result + conformanceLevel.hashCode()
        result = 31 * result + signAlgo.hashCode()
        result = 31 * result + (signAlgoParams?.hashCode() ?: 0)
        result = 31 * result + (signedProps?.hashCode() ?: 0)
        result = 31 * result + signedEnvelopeProperty.hashCode()
        return result
    }
}



