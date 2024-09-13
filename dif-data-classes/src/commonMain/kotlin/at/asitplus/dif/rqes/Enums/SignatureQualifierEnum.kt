package at.asitplus.dif.rqes.Enums

import kotlinx.serialization.SerialName

@Suppress("unused")
enum class SignatureQualifierEnum {

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
