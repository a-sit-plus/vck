package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

/**
 * Each Zk system should register serializers for its param keys to allow [ZkSystemSpec.params] to be properly
 * deserialized into a Map<String, Any>
 */
@OptIn(ExperimentalAtomicApi::class)
object ZkSystemParamRegistry {

    private val serializerMapRef = AtomicReference(mapOf<String, Map<String, KSerializer<*>>>())

    private val serializerMap: Map<String, Map<String, KSerializer<*>>>
        get() = serializerMapRef.load()

    /**
     * Registers param serializers for a specific Iso mDoc ZK proof system.
     * If the same [systemName] is already registered, compatible serializers are merged
     */
    fun register(systemName: String, paramSerializers: Map<String, KSerializer<*>>) {
        serializerMapRef.update { current ->
            val existing = current[systemName].orEmpty()
            if (!existing.isCompatibleWith(paramSerializers)) {
                throw IllegalStateException(
                    "Conflicting param serializers for ZK system '$systemName'. " +
                            "Existing: ${existing.mapValues { it.value.descriptor.serialName }}, " +
                            "New: ${paramSerializers.mapValues { it.value.descriptor.serialName }}"
                )
            }

            current + (systemName to (existing + paramSerializers))
        }
    }

    fun lookupSerializer(systemName: String, paramKey: String): KSerializer<*>?
            = serializerMap[systemName]?.get(paramKey)

}

private fun Map<String, KSerializer<*>>.isCompatibleWith(otherSerializers: Map<String, KSerializer<*>>): Boolean =
    this.keys.intersect(otherSerializers.keys).all { this[it] == otherSerializers[it] }
