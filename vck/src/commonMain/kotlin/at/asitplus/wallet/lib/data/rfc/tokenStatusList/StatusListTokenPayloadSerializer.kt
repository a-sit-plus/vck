package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CwtStatusListTokenPayload.Companion.toCwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JwtStatusListTokenPayload.Companion.toJwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CwtStatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JwtStatusListTokenPayload
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder

/**
 * Workaround to support serialization without type discriminator.
 */
@ExperimentalUnsignedTypes
object StatusListTokenPayloadSerializer : KSerializer<StatusListTokenPayload> {
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            // TODO: how to properly write a serial descriptor for a format specific serializer?
            //  - serial kind is not constant?
            serialName = StatusListTokenPayload::class.qualifiedName!!,
            original = JwtStatusListTokenPayload.serializer().descriptor,
        )

    override fun deserialize(decoder: Decoder): StatusListTokenPayload {
        return when (decoder) {
            is JsonDecoder -> JwtStatusListTokenPayload.serializer().deserialize(decoder)
                .toStatusListTokenPayload()

            is CborDecoder -> CwtStatusListTokenPayload.serializer().deserialize(decoder)
                .toStatusListTokenPayload()

            else -> throw IllegalArgumentException("Argument `decoder` must be a subtype of one of the following classes: [${
                listOf(
                    JsonDecoder::class,
                    CborDecoder::class,
                ).joinToString(", ") {
                    it.qualifiedName!!
                }
            }]")
        }
    }

    override fun serialize(encoder: Encoder, value: StatusListTokenPayload) {
        return when (encoder) {
            is JsonEncoder -> JwtStatusListTokenPayload.serializer()
                .serialize(encoder, value.toJwtStatusListTokenPayload())

            is CborEncoder -> CwtStatusListTokenPayload.serializer()
                .serialize(encoder, value.toCwtStatusListTokenPayload())

            else -> throw IllegalArgumentException("Argument `encoder` must be a subtype of one of the following classes: [${
                listOf(
                    JsonEncoder::class,
                    CborEncoder::class,
                ).joinToString(", ") {
                    it.qualifiedName!!
                }
            }]")
        }
    }
}