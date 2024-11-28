package at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder

/**
 * Workaround to support serialization without type discriminator for different serialization
 * formats.
 */
class FormatTransformingSerializerTemplate<Original, JsonSurrogate, CborSurrogate> (
    // TODO: how to specify this format-dependently?
    override val descriptor: SerialDescriptor,
    val jsonTransformer: TransformingSerializerTemplate<Original, JsonSurrogate>,
    val cborTransformer: TransformingSerializerTemplate<Original, CborSurrogate>,
) : KSerializer<Original> {
    override fun deserialize(decoder: Decoder): Original {
        return when (decoder) {
            is JsonDecoder -> jsonTransformer

            is CborDecoder -> cborTransformer

            else -> {
                throw IllegalArgumentException("Argument `decoder` uses an experimental format, the result may be incorrect. Supported formats: [${
                    listOf(
                        JsonDecoder::class,
                        CborDecoder::class,
                    ).joinToString(", ") {
                        it.qualifiedName!!
                    }
                }]")
            }
        }.deserialize(decoder)
    }

    override fun serialize(encoder: Encoder, value: Original) {
        return when (encoder) {
            is JsonEncoder -> jsonTransformer

            is CborEncoder -> cborTransformer

            else -> {
                throw IllegalArgumentException("Argument `encoder` uses an experimental format, the result may be incorrect. Supported formats: [${
                    listOf(
                        JsonEncoder::class,
                        CborDecoder::class,
                    ).joinToString(", ") {
                        it.qualifiedName!!
                    }
                }]")
            }
        }.serialize(encoder, value)
    }
}
