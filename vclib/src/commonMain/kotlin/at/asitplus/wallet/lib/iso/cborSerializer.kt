package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.DescriptorLookup
import at.asitplus.wallet.lib.ItemValueEncoder
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeEncoder

object Cbor {

    private val descriptorLookupFunctions = mutableSetOf<DescriptorLookup>()
    private val encoderFunctions = mutableSetOf<ItemValueEncoder>()

    init {
        descriptorLookupFunctions += {
            when (it) {
                is Array<*> -> ArraySerializer(DrivingPrivilege.serializer())
                else -> null
            }
        }
        encoderFunctions += { descriptor, index, compositeEncoder, value ->
            if (value is Array<*>) {
                true.also {
                    @Suppress("UNCHECKED_CAST")
                    compositeEncoder.encodeSerializableElement(
                        descriptor,
                        index,
                        ArraySerializer(DrivingPrivilege.serializer()),
                        value as Array<DrivingPrivilege>
                    )
                }
            } else {
                false
            }
        }
    }

    fun register(function: DescriptorLookup) {
        descriptorLookupFunctions += function
    }

    fun register(function: ItemValueEncoder) {
        encoderFunctions += function
    }

    fun lookupDescriptor(element: Any): KSerializer<*>? {
        return descriptorLookupFunctions.firstNotNullOfOrNull { it.invoke(element) }
    }

    fun encode(descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, value: Any) {
        encoderFunctions.firstOrNull { it.invoke(descriptor, index, compositeEncoder, value) }
    }
}

@OptIn(ExperimentalSerializationApi::class)
val cborSerializer by lazy {
    Cbor {
        ignoreUnknownKeys = true
        alwaysUseByteString = true
        encodeDefaults = false
        writeDefiniteLengths = true
    }
}