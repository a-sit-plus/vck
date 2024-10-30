package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

/**
 * Encodes [SelectiveDisclosureItem] as needed by SD-JWT spec,
 * that is a JSON array with the values for salt, name, and the value itself,
 * which in turn can be anything, e.g. number, boolean or string.
 * We solve this challenge by serializing a list of [JsonPrimitive], see implementation.
 * Note, that when disclosing array items, the claim name may be missing.
 */
object SelectiveDisclosureItemSerializer : KSerializer<SelectiveDisclosureItem> {

    private val listSerializer = ListSerializer(JsonElement.serializer())

    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun serialize(encoder: Encoder, value: SelectiveDisclosureItem) {
        encoder.encodeSerializableValue(
            listSerializer,
            listOfNotNull(
                JsonPrimitive(value.salt.encodeToString(Base64UrlStrict)),
                value.claimName?.let { JsonPrimitive(value.claimName) },
                value.claimValue
            )
        )
    }

    override fun deserialize(decoder: Decoder): SelectiveDisclosureItem {
        return with(decoder.decodeSerializableValue(listSerializer)) {
            when (size) {
                3 -> SelectiveDisclosureItem(
                    salt = get(0).jsonPrimitive.content.decodeToByteArray(Base64UrlStrict),
                    claimName = get(1).jsonPrimitive.content,
                    claimValue = get(2)
                )

                2 -> SelectiveDisclosureItem(
                    salt = get(0).jsonPrimitive.content.decodeToByteArray(Base64UrlStrict),
                    claimName = null,
                    claimValue = get(1)
                )

                else -> throw IllegalArgumentException("Neither 2 nor 3 elements")
            }
        }
    }

}