package at.asitplus.wallet.lib.data.rfc7519.primitives

import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder

class ListSingleItemInlineSerializer<T>(
    val itemSerializer: KSerializer<T>,
) : KSerializer<List<T>> {
    private val listSerializer = ListSerializer(itemSerializer)
    override val descriptor: SerialDescriptor
        get() = listSerializer.descriptor

    override fun deserialize(decoder: Decoder): List<T> {
        return when (decoder) {
            is JsonDecoder -> {
                val array = decoder.decodeJsonElement().let {
                    if (it !is JsonArray) JsonArray(listOf(it))
                    else it
                }

                array.map {
                    decoder.json.decodeFromJsonElement(itemSerializer, it)
                }
            }

            // This works for Cbor, but hasn't been tested for other formats
            else -> {
                if(decoder !is CborDecoder) {
                    Napier.w("Argument `decoder` uses an experimental format, results may be incorrect. Supported formats: ${
                        listOf(Json::class, Cbor::class).joinToString(", ") {
                            it.qualifiedName!!
                        }
                    }")
                }
                val result = mutableListOf<T>()
                try {
                    decoder.decodeStructure(descriptor) {
                        while (true) {
                            val index = decodeElementIndex(descriptor)

                            when (index) {
                                CompositeDecoder.DECODE_DONE -> {
                                    break
                                }
                            }
                            result.add(
                                decodeSerializableElement(itemSerializer.descriptor, index, itemSerializer)
                            )
                        }
                    }
                } catch (_: Throwable) {
                    result.add(decoder.decodeSerializableValue(itemSerializer))
                }
                result
            }
        }
    }

    override fun serialize(encoder: Encoder, value: List<T>) {
        if(value.size == 1) {
            itemSerializer.serialize(encoder, value.first())
        } else {
            listSerializer.serialize(
                encoder,
                value
            )
        }
    }
}