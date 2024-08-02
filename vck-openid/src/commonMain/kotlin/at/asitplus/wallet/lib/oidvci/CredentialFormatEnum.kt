package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = CredentialFormatSerializer::class)
enum class CredentialFormatEnum(val text: String) {
    NONE("none"),
    JWT_VC("jwt_vc_json"),
    /**
     * Unofficial constant, used by this library prior to implementing OID4VCI Draft 13.
     */
    JWT_VC_SD_UNOFFICIAL("jwt_vc_sd"),
    VC_SD_JWT("vc+sd-jwt"),
    JWT_VC_JSON_LD("jwt_vc_json-ld"),
    JSON_LD("ldp_vc"),
    MSO_MDOC("mso_mdoc");

    companion object {
        fun parse(text: String) = entries.firstOrNull { it.text == text }
    }
}

object CredentialFormatSerializer : KSerializer<CredentialFormatEnum> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("CredentialFormatEnumSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: CredentialFormatEnum) {
        encoder.encodeString(value.text)
    }

    override fun deserialize(decoder: Decoder): CredentialFormatEnum {
        return CredentialFormatEnum.parse(decoder.decodeString()) ?: CredentialFormatEnum.NONE
    }
}