package at.asitplus.wallet.lib.data.rfc7519.primitives

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.decodeFromJsonElement

object AudienceInlineSerializer : KSerializer<Audience> {
    private val listSerializer = ListSerializer(StringOrURIInlineSerializer)
    override val descriptor: SerialDescriptor
        get() = listSerializer.descriptor

    override fun deserialize(decoder: Decoder): Audience {
        return when (decoder) {
            is JsonDecoder -> {
                val array = decoder.decodeJsonElement().let {
                    if (it !is JsonArray) JsonArray(listOf(it))
                    else it
                }

                array.map {
                    decoder.json.decodeFromJsonElement<StringOrURI>(it)
                }
            }

            // This works for Cbor, but hasn't been tested for other formats
            else -> {
                val result = mutableListOf<String>()
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
                                decodeStringElement(listSerializer.descriptor, index)
                            )
                        }
                    }
                } catch (_: Throwable) {
                    result.add(decoder.decodeString())
                }
                result.map {
                    StringOrURI(it)
                }
            }
        }.let {
            Audience(it)
        }
    }

    override fun serialize(encoder: Encoder, value: Audience) {
        listSerializer.serialize(encoder, value.value)
    }
}