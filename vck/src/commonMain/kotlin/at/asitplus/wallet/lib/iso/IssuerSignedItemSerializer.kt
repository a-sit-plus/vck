package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.InstantStringSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.*

internal class IssuerSignedItemCosef(val docType: String)

open class IssuerSignedItemSerializer(private val docType: String) : KSerializer<IssuerSignedItem> {

    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("IssuerSignedItem") {
        element("digestID", Long.serializer().descriptor)
        element("random", ByteArraySerializer().descriptor)
        element("elementIdentifier", String.serializer().descriptor)
        element("elementValue", String.serializer().descriptor)
    }

    override fun serialize(encoder: Encoder, value: IssuerSignedItem) {
        encoder.encodeStructure(descriptor) {
            encodeLongElement(descriptor, 0, value.digestId.toLong())
            encodeSerializableElement(descriptor, 1, ByteArraySerializer(), value.random)
            encodeStringElement(descriptor, 2, value.elementIdentifier)
            encodeAnything(value, 3)
        }
    }

    private fun CompositeEncoder.encodeAnything(value: IssuerSignedItem, index: Int) {
        val descriptor = buildClassSerialDescriptor("IssuerSignedItem") {
            element("digestID", Long.serializer().descriptor)
            element("random", ByteArraySerializer().descriptor)
            element("elementIdentifier", String.serializer().descriptor)
            element(
                elementName = "elementValue",
                descriptor = buildElementValueSerializer(value.elementValue).descriptor,
                annotations = if (value.elementValue is LocalDate || value.elementValue is Instant)
                    listOf(ValueTags(1004uL)) else emptyList()
            )
        }

        when (val it = value.elementValue) {
            is String -> encodeStringElement(descriptor, index, it)
            is Int -> encodeIntElement(descriptor, index, it)
            is LocalDate -> encodeSerializableElement(descriptor, index, LocalDate.serializer(), it)
            is Instant -> encodeSerializableElement(descriptor, index, InstantStringSerializer(), it)
            is Boolean -> encodeBooleanElement(descriptor, index, it)
            is ByteArray -> encodeSerializableElement(descriptor, index, ByteArraySerializer(), it)
            else -> CborCredentialSerializer.encode(descriptor, index, this, it)
        }
    }

    private inline fun <reified T> buildElementValueSerializer(element: T) = when (element) {
        is String -> String.serializer()
        is Int -> Int.serializer()
        is LocalDate -> LocalDate.serializer()
        is Instant -> InstantStringSerializer()
        is Boolean -> Boolean.serializer()
        is ByteArray -> ByteArraySerializer()
        is Any -> CborCredentialSerializer.lookupSerializer(element) ?: error("descriptor not found for $element")
        else -> error("descriptor not found for $element")
    }


    override fun deserialize(decoder: Decoder): IssuerSignedItem {
        var digestId = 0U
        lateinit var random: ByteArray
        lateinit var elementIdentifier: String
        lateinit var elementValue: Any
        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = decodeStringElement(descriptor, 0)
                val index =
                    descriptor.getElementIndex(name) //todo: decodeElementIndex does not work here, but is the only function that parses tags
                when (name) {
                    "digestID" -> digestId = decodeLongElement(descriptor, index).toUInt()
                    "random" -> random = decodeSerializableElement(descriptor, index, ByteArraySerializer())
                    "elementIdentifier" -> elementIdentifier = decodeStringElement(descriptor, index)
                    "elementValue" -> elementValue = decodeAnything(index, elementIdentifier)
                }
                if (index == 3) break
            }
        }
        return IssuerSignedItem(
            digestId = digestId,
            random = random,
            elementIdentifier = elementIdentifier,
            elementValue = elementValue
        )
    }

    private fun CompositeDecoder.decodeAnything(index: Int, elementIdentifier: String): Any {
        if (docType.isBlank()) Napier.w { "Danger, Will Robinson! this decoder is not docType-aware! Unspeakable things may happen…" }

        //TODO: tags are not read out here because `decodeElementIndex` is never called, so we cannot discriminate

        //TODO: this fails, because the date is a valid string, but date parsing does not work, so the data was already consumed from the source and parsing it again will fail
        runCatching {

            CborCredentialSerializer.decode(descriptor, index, this, elementIdentifier, docType)?.let {
                return it
            }
                ?: Napier.w { "Could not find a registered decoder for docType $docType and elementIdentifier $elementIdentifier. Falling back to defaults" }

        }


        runCatching { return decodeStringElement(descriptor, index) }.exceptionOrNull()?.printStackTrace()
        runCatching { return decodeBooleanElement(descriptor, index) }.exceptionOrNull()?.printStackTrace()

        throw IllegalArgumentException("Could not decode value at $index")
    }
}