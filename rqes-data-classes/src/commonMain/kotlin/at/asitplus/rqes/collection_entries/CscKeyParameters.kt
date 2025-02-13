package at.asitplus.rqes.collection_entries

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CscKeyParameters(
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
    val algo: Collection<ObjectIdentifier>,

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
    val curve: ObjectIdentifier? = null,
) {
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