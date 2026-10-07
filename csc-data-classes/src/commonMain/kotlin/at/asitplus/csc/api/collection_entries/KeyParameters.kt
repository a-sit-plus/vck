package at.asitplus.csc.api.collection_entries

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.csc.api.CredentialInfo
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC-API v2.0.0.2
 * Part of [CredentialInfo]
 */
@Serializable
data class KeyParameters(
    /**
     * REQUIRED.
     * The status of the signing key of the credential:
     */
    @SerialName("status")
    val status: KeyStatusOptions,

    /**
     * REQUIRED.
     * The list of OIDs of the supported key algorithms
     */
    @SerialName("algo")
    val algo: Set<@Serializable(with = ObjectIdentifierStringSerializer::class) ObjectIdentifier>,

    /**
     * REQUIRED.
     * The length of the cryptographic key in bits.
     */
    @SerialName("len")
    val len: UInt,

    /**
     * REQUIRED-CONDITIONAL
     * The OID of the ECDSA curve. The value SHALL only be returned if
     * [algo] is based on ECDSA.
     */
    @SerialName("curve")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val curve: ObjectIdentifier? = null,
) {
    init {
        require(
            algo.intersect(
                listOf(
                    EcdsaAlgorithm.withSHA256.asn1Representation.oid,
                    EcdsaAlgorithm.withSHA384.asn1Representation.oid,
                    EcdsaAlgorithm.withSHA512.asn1Representation.oid
                ).toSet()
            ) != emptySet<ObjectIdentifier>() || curve == null
        ) { "If curve is specified algorithm must be (supported) EC algorithm" }
    }

    enum class KeyStatusOptions {
        /**
         * the signing key is enabled and can be used for signing.
         */
        @SerialName("enabled")
        ENABLED,

        /**
         * the signing key is disabled and cannot be used for
         * signing. This MAY occur when the owner has disabled it or when
         * the RSSP has detected that the associated certificate is expired or
         * revoked.
         */
        @SerialName("disabled")
        DISABLED
    }
}
