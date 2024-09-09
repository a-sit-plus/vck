package at.asitplus.dif.rqes.DocumentDigestEntries

import at.asitplus.dif.rqes.ConformanceLevelEnum
import at.asitplus.dif.rqes.SignatureFormat
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

data class CscDocumentDigestEntry(
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


    val signatureFormat: SignatureFormat,


    val conformanceLevel: ConformanceLevelEnum = ConformanceLevelEnum.ADESBB,
    val signAlgo: String,
    val signAlgoParams: String,
    val signedProps: List<String>,
    val signedEnvelopeProperty: String,
)

