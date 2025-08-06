package at.asitplus.csc.enums

import kotlinx.serialization.SerialName

/**
 * Specifies which certificates from the certificate chain SHALL be returned
 */
enum class CertificateOptions {
    /**
     * No certificate SHALL be returned
     */
    @SerialName("none")
    NONE,

    /**
     * Only the end entity certificate SHALL be returned.
     */
    @SerialName("single")
    SINGLE,

    /**
     * The full certificate chain SHALL be returned.
     */
    @SerialName("chain")
    CHAIN,
}