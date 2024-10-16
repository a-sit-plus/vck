package at.asitplus.rqes.enums

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC v2.0.0.2 Signature formats
 */
@Suppress("unused")
@Serializable
enum class SignatureFormat {
    /**
     * “C” SHALL be used to request the creation of a CAdES signature;
     */
    @SerialName("C")
    CADES,

    /**
     * “X” SHALL be used to request the creation of a XAdES signature.
     */
    @SerialName("X")
    XADES,

    /**
     * “P” SHALL be used to request the creation of a PAdES signature.
     */
    @SerialName("P")
    PADES,

    /**
     * “J” SHALL be used to request the creation of a JAdES signature.
     */
    @SerialName("J")
    JADES,
}