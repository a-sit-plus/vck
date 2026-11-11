package at.asitplus.wallet.lib.data

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

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
                JsonPrimitive(value.salt),
                value.claimName?.let { JsonPrimitive(value.claimName) },
                value.claimValue
            )
        )
    }

    override fun deserialize(decoder: Decoder): SelectiveDisclosureItem =
        with(decoder.decodeSerializableValue(listSerializer)) {
            when (size) {
                // Object property: salt, claim name, claim value (RFC 9901, 4.2.1)
                3 -> SelectiveDisclosureItem(
                    salt = get(0).string("salt"),
                    claimName = get(1).string("claim name"),
                    claimValue = get(2)
                )

                // Array element: salt, value (RFC 9901, 4.2.2)
                2 -> SelectiveDisclosureItem(
                    salt = get(0).string("salt"),
                    claimName = null,
                    claimValue = get(1)
                )

                else -> throw SerializationException("A disclosure has 2 or 3 elements, not $size")
            }
        }

    /** The salt and the claim name "MUST be a string" (RFC 9901, 4.2.1), so `null`, numbers and booleans are not. */
    private fun JsonElement.string(name: String): String =
        (this as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw SerializationException("The $name of a disclosure must be a string: $this")

}