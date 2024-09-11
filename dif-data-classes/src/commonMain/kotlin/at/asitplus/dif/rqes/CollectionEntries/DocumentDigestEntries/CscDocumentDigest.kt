package at.asitplus.dif.rqes.CollectionEntries.DocumentDigestEntries

import at.asitplus.dif.rqes.Enums.ConformanceLevelEnum
import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


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
    val hashes: List<@Serializable(ByteArrayBase64Serializer::class) ByteArray>,
    /**
     * Hashing algorithm OID used to calculate document(s) hash(es). This
     * parameter MAY be omitted or ignored if the hash algorithm is
     * implicitly specified by the signAlgo algorithm. Only hashing algorithms
     * as strong or stronger than SHA256 SHALL be used
     */
    @SerialName("hashAlgorithmOid")
    val hashAlgorithmOid: ObjectIdentifier,

    /**
     * Requested Signature Format
     */
    val signatureFormat: SignatureFormat,


    /**
     * Requested conformance level. If omitted its value is "Ades-B-B"
     */
    val conformanceLevel: ConformanceLevelEnum = ConformanceLevelEnum.ADESBB,

    /**
     * The OID of the algorithm to use for signing
     */
    val signAlgo: ObjectIdentifier,

    /**
     * TODO: Serializer
     * The Base64-encoded DER-encoded ASN.1 signature parameters
     */
    val signAlgoParams: String,

    val signedProps: List<String>?,
    val signedEnvelopeProperty: SignedEnvelopeProperty = SignedEnvelopeProperty.defaultProperty(signatureFormat),
)

