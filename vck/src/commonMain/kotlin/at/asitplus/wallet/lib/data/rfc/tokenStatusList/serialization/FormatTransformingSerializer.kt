package at.asitplus.wallet.lib.data.rfc.tokenStatusList.serialization

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder

/**
 * Workaround to support format specific serialization without type discriminator.
 */
class FormatTransformingSerializerTemplate<Original, FallbackSurrogate, JsonSurrogate, CborSurrogate> (
    val fallbackTransformer: TransformingSerializerTemplate<Original, FallbackSurrogate>,
    val jsonTransformer: TransformingSerializerTemplate<Original, JsonSurrogate>,
    val cborTransformer: TransformingSerializerTemplate<Original, CborSurrogate>,
) : KSerializer<Original> {
    override val descriptor: SerialDescriptor
        get() = fallbackTransformer.descriptor

    override fun deserialize(decoder: Decoder): Original {
        return when (decoder) {
            is JsonDecoder -> jsonTransformer

            is CborDecoder -> cborTransformer

            else -> {
                Napier.w("Argument `decoder` uses an experimental format, the result may be incorrect. Supported formats: [${
                    listOf(
                        JsonDecoder::class,
                        CborDecoder::class,
                    ).joinToString(", ") {
                        it.qualifiedName!!
                    }
                }]")
                fallbackTransformer
            }
        }.deserialize(decoder)
    }

    override fun serialize(encoder: Encoder, value: Original) {
        return when (encoder) {
            is JsonEncoder -> jsonTransformer

            is CborEncoder -> cborTransformer

            else -> {
                Napier.w("Argument `encoder` uses an experimental format, the result may be incorrect. Supported formats: [${
                    listOf(
                        JsonEncoder::class,
                        CborDecoder::class,
                    ).joinToString(", ") {
                        it.qualifiedName!!
                    }
                }]")
                fallbackTransformer
            }
        }.serialize(encoder, value)
    }
}
