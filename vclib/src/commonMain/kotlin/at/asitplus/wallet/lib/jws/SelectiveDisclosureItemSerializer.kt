package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object SelectiveDisclosureItemSerializer : KSerializer<SelectiveDisclosureItem> {

    private val listSerializer = ListSerializer(String.serializer())

    override val descriptor: SerialDescriptor = listSerializer.descriptor

    override fun serialize(encoder: Encoder, value: SelectiveDisclosureItem) {
        encoder.encodeSerializableValue(
            listSerializer,
            listOf(value.salt.encodeToString(Base64UrlStrict), value.claimName, value.claimValue)
        )
    }

    override fun deserialize(decoder: Decoder): SelectiveDisclosureItem {
        val items = decoder.decodeSerializableValue(listSerializer)
        if (items.count() != 3) throw IllegalArgumentException()
        return SelectiveDisclosureItem(
            salt = items[0].decodeToByteArray(Base64UrlStrict),
            claimName = items[1],
            claimValue = items[2]
        )
    }

}