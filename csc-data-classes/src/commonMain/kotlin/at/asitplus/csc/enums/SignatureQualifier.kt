package at.asitplus.csc.enums

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * CSC API v2.1.0.1 Ch 11.12
 */
@Suppress("unused")
@Serializable
enum class SignatureQualifier {

    @SerialName("eu_eidas_qes")
    EU_EIDAS_QES,

    @SerialName("eu_eidas_aes")
    EU_EIDAS_AES,

    @SerialName("eu_eidas_aesqc")
    EU_EIDAS_AESQC,

    @SerialName("eu_eidas_qeseal")
    EU_EIDAS_QESEAL,

    @SerialName("eu_eidas_aeseal")
    EU_EIDAS_AESEAL,

    @SerialName("eu_eidas_aesealqc")
    EU_EIDAS_AESEALQC,
}