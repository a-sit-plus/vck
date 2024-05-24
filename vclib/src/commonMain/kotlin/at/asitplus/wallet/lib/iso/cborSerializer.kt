package at.asitplus.wallet.lib.iso

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeEncoder

object Cbor {
    inline fun <T> lookupDescriptor(element: T): KSerializer<*>? {
        return when (element) {
            is Array<*> -> ArraySerializer(DrivingPrivilege.serializer())
            else -> null
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun encode(descriptor: SerialDescriptor, index: Int, compositeEncoder: CompositeEncoder, it: Any) {
        if (it is Array<*>) {
            compositeEncoder.encodeSerializableElement(
                descriptor,
                index,
                ArraySerializer(DrivingPrivilege.serializer()),
                it as Array<DrivingPrivilege>
            )
        }
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