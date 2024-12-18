package at.asitplus.rqes.enums

import kotlinx.serialization.SerialName

enum class CertificateOptions {
    @SerialName("none")
    NONE,

    @SerialName("single")
    SINGLE,

    @SerialName("chain")
    CHAIN,
}