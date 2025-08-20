package at.asitplus.rqes.enums

import kotlinx.serialization.SerialName

/**
 * Specifies which certificates from the certificate chain SHALL be returned
 */

@Deprecated(
    "Module will be removed in the future",
    ReplaceWith(
        "CertificateOptions",
        imports = ["at.asitplus.csc.enums.CertificateOptions"]
    )
)
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