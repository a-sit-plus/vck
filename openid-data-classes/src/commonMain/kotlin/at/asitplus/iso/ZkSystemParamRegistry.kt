package at.asitplus.iso

import kotlinx.serialization.KSerializer

/**
 * Each Zk system should register serializers for its param keys to allow [ZkSystemSpec.params] to be properly
 * deserialized into a Map<String, Any>
 */
object ZkSystemParamRegistry {
    private val serializerMap = mutableMapOf<String, Map<String, KSerializer<*>>>()

    /**
     * Registers param serializers for a specific Iso mDoc ZK proof system.
     * If the same [systemName] is already registered, compatible serializers are merged
     */
    fun register(systemName: String, paramSerializers: Map<String, KSerializer<*>>) {
        serializerMap[systemName]?.let { existing ->
            if (!existing.isCompatibleWith(paramSerializers)) {
                throw IllegalStateException(
                    "Conflicting param serializers for ZK system '$systemName'. " +
                            "Existing: ${existing.mapValues { it.value.descriptor.serialName }}, " +
                            "New: ${paramSerializers.mapValues { it.value.descriptor.serialName }}"
                )
            }
            serializerMap[systemName] = existing + paramSerializers
            return

        }

        serializerMap[systemName] = paramSerializers
    }

    fun lookupSerializer(systemName: String, paramKey: String): KSerializer<*>?
            = serializerMap[systemName]?.get(paramKey)

}

private fun Map<String, KSerializer<*>>.isCompatibleWith(otherSerializers: Map<String, KSerializer<*>>): Boolean =
    this.keys.intersect(otherSerializers.keys).all { this[it] == otherSerializers[it] }
