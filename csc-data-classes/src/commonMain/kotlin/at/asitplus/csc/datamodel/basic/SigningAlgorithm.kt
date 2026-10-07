package at.asitplus.csc.datamodel.basic

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.csc.api.serializers.Asn1EncodableBase64Serializer
import at.asitplus.csc.getSignAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Cryptographic signing algorithm parameters from CSC Data Model 1.0.0 section 7.6. */
@Serializable
data class SigningAlgorithm(
    /**
     * CSC Data Model 1.0.0 section 7.6: REQUIRED
     * Signature algorithm object identifier.
     */
    @SerialName("signAlgo")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val signAlgo: ObjectIdentifier,
    /**
     * CSC Data Model 1.0.0 section 7.6: CONDITIONAL
     * Required by some signature algorithms; DER-encoded and Base64-encoded.
     */
    @SerialName("signAlgoParams")
    @Serializable(with = Asn1EncodableBase64Serializer::class)
    val signAlgoParams: Asn1Element? = null,
) {
    /** Returns the matching Signum algorithm when Signum knows this OID/parameter combination. */
    fun toSignatureAlgorithmOrNull(): SignatureAlgorithm? = signAlgo.getSignAlgorithm(signAlgoParams)
}
