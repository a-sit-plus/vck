package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.ItemValueDecoder
import at.asitplus.wallet.lib.ItemValueEncoder
import at.asitplus.wallet.lib.SerializerLookup
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.CompositeEncoder

internal object CborCredentialSerializer {

    private val serializerLookupFunctions = mutableSetOf<SerializerLookup>()
    private val encoderFunctions = mutableSetOf<ItemValueEncoder>()
    private val decoderMap = mutableMapOf<String, Map<String, ItemValueDecoder>>()

    fun register(function: SerializerLookup) {
        serializerLookupFunctions += function
    }

    fun register(function: ItemValueEncoder) {
        encoderFunctions += function
    }


    fun register(serializerMap: Map<String, KSerializer<*>>, isoNamespace: String) {
        decoderMap[isoNamespace] =
            serializerMap.map { (k, ser) ->
                k to { descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder ->
                    compositeDecoder.decodeSerializableElement(
                        descriptor,
                        index,
                        ser
                    )!!
                }
            }.toMap()
    }

    fun lookupSerializer(element: Any): KSerializer<*>? {
        return serializerLookupFunctions.firstNotNullOfOrNull { it.invoke(element) }
    }

    fun encode(descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) {
        encoderFunctions.firstOrNull { it.invoke(descriptor, index, compositeEncoder, value) }
    }

    fun decode(
        descriptor: SerialDescriptor,
        index: Int,
        compositeDecoder: CompositeDecoder,
        elementIdentifier: String,
        isoDocType: String
    ): Any? =
        decoderMap[isoDocType]?.get(elementIdentifier)?.let {
            runCatching { it.invoke(descriptor, index, compositeDecoder) }.getOrNull()
        }
}

@Deprecated("use vckCborSerializer instead", replaceWith = ReplaceWith("vckCborSerializer"))
val cborSerializer get() = vckCborSerializer

@OptIn(ExperimentalSerializationApi::class)
val vckCborSerializer by lazy {
    Cbor(from = at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer) {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
    }
}
