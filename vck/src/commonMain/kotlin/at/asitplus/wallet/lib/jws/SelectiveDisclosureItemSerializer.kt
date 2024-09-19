package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Encodes [SelectiveDisclosureItem] as needed by SD-JWT spec,
 * that is a JSON array with the values for salt, name, and the value itself,
 * which in turn can be anything, e.g. number, boolean or string.
 * We solve this challenge by serializing a list of [JsonPrimitive], see implementation.
 */
object SelectiveDisclosureItemSerializer : KSerializer<SelectiveDisclosureItem> {

    private val listSerializer = ListSerializer(JsonPrimitive.serializer())

    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun serialize(encoder: Encoder, value: SelectiveDisclosureItem) {
        val valueElement = when (val value = value.claimValue) {
            is Boolean -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is ByteArray -> JsonPrimitive(value.encodeToString(Base64UrlStrict))
            else -> JsonPrimitive(value.toString())
        }
        encoder.encodeSerializableValue(
            listSerializer,
            listOf(
                JsonPrimitive(value.salt.encodeToString(Base64UrlStrict)),
                JsonPrimitive(value.claimName),
                valueElement
            )
        )
    }

    override fun deserialize(decoder: Decoder): SelectiveDisclosureItem {
        val items = decoder.decodeSerializableValue(listSerializer)
        if (items.count() != 3) throw IllegalArgumentException()
        val (firstElement, secondElement, thirdElement) = items
        return SelectiveDisclosureItem(
            salt = firstElement.content.decodeToByteArray(Base64UrlStrict),
            claimName = secondElement.content,
            claimValue = thirdElement.booleanOrNull
                ?: thirdElement.longOrNull
                ?: thirdElement.intOrNull
                ?: thirdElement.doubleOrNull
                ?: thirdElement.floatOrNull
                ?: runCatching { thirdElement.content.decodeToByteArray(Base64UrlStrict) }.getOrNull()
                ?: thirdElement.content
        )
    }

}