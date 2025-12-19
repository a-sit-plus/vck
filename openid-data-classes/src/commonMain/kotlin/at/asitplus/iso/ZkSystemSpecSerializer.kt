package at.asitplus.iso

import at.asitplus.catchingUnwrapped
import io.github.aakira.napier.Napier
import kotlinx.datetime.LocalDate
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlin.time.Instant

object ZkSystemSpecSerializer : KSerializer<ZkSystemSpec> {
    override val descriptor = buildClassSerialDescriptor("ZkSystemSpec") {
        element(ZkSystemSpec.PROP_ZK_SYSTEM_ID, String.serializer().descriptor)
        element(ZkSystemSpec.PROP_SYSTEM, String.serializer().descriptor)
        element(ZkSystemSpec.PROP_PARAMS, ZkSystemParamsMapSerializer("dummy").descriptor)
    }
    override fun deserialize(decoder: Decoder): ZkSystemSpec {
        var zkSystemId: String? = null
        var system: String? = null
        var params: Map<String, Any>? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val name = decodeStringElement(descriptor, 0)
                val index = descriptor.getElementIndex(name)

                when(name) {
                    ZkSystemSpec.PROP_ZK_SYSTEM_ID -> zkSystemId = decodeStringElement(descriptor, index)
                    ZkSystemSpec.PROP_SYSTEM -> system = decodeStringElement(descriptor, index)
                    ZkSystemSpec.PROP_PARAMS -> {
                        params = decodeSerializableElement(
                            descriptor, index,
                            ZkSystemParamsMapSerializer(system ?: "")
                        )
                    }
                }

                if (zkSystemId != null && system != null && params != null) break
            }
        }

        return ZkSystemSpec(
            zkSystemId = zkSystemId ?: error("Missing zkSystemId"),
            system = system ?: error("Missing system"),
            params = params ?: error("Missing params"),
        )
    }

    override fun serialize(encoder: Encoder, value: ZkSystemSpec) {
        ZkSystemParamsMapSerializer(value.system).let { paramsSerializer ->
            encoder.encodeStructure(descriptor) {
                encodeStringElement(descriptor, 0, value.zkSystemId)
                encodeStringElement(descriptor, 1, value.system)
                encodeSerializableElement(descriptor, 2, paramsSerializer, value.params)
            }
        }

    }
}

internal class ZkSystemParamsMapSerializer(
    private val systemName: String,
): KSerializer<Map<String, Any>> {
    @OptIn(InternalSerializationApi::class)
    override val descriptor = buildSerialDescriptor("ZkSystemParams", StructureKind.MAP)


    override fun serialize(encoder: Encoder, value: Map<String, Any>) {
        ParamMapEntrySerializer().let {entrySerializer ->
            MapSerializer(entrySerializer.keySerializer, entrySerializer.valueSerializer).serialize(encoder, value)
        }
    }
    override fun deserialize(decoder: Decoder): Map<String, Any> {
        return ParamMapEntrySerializer().let {entrySerializer ->
            MapSerializer(entrySerializer.keySerializer, entrySerializer.valueSerializer).deserialize(decoder)
        }
    }

    private inner class ParamMapEntrySerializer {
        lateinit var currentKey: String

        val keySerializer = object: KSerializer<String> {
            override val descriptor = PrimitiveSerialDescriptor("ParamKey", PrimitiveKind.STRING)

            override fun serialize(encoder: Encoder, value: String) {
                currentKey = value
                encoder.encodeString(value)
            }

            override fun deserialize(decoder: Decoder): String {
                return decoder.decodeString().also {currentKey = it}
            }
        }

        val valueSerializer = object : KSerializer<Any> {
            override val descriptor = PrimitiveSerialDescriptor("ValueKey", PrimitiveKind.STRING)

            override fun serialize(encoder: Encoder, value: Any) {
                ZkSystemParamRegistry.lookupSerializer(systemName, currentKey)?.let { serializer ->
                    @Suppress("UNCHECKED_CAST")
                    encoder.encodeSerializableValue(serializer as KSerializer<Any>, value)
                    return
                }
                Napier.d("param '$currentKey' not registered, using defaults")
                when (value) {
                    is String -> encoder.encodeString(value)
                    is Int -> encoder.encodeInt(value)
                    is Long -> encoder.encodeLong(value)
                    is LocalDate -> encoder.encodeSerializableValue(LocalDate.serializer(), value)
                    is Instant -> encoder.encodeSerializableValue(InstantStringSerializer, value)
                    is Boolean -> encoder.encodeBoolean(value)
                    is ByteArray -> encoder.encodeSerializableValue(ByteArraySerializer(), value)
                    else -> error("Unexpected value: $value")
                }


            }

            override fun deserialize(decoder: Decoder): Any {
                ZkSystemParamRegistry.lookupSerializer(systemName, currentKey)?.let { serializer ->
                    @Suppress("UNCHECKED_CAST")
                    return decoder.decodeSerializableValue(serializer)
                        ?: error("Null value for param '$currentKey' is not supported")
                }
                Napier.d("param '$currentKey' not registered, using fallbacks to")
                catchingUnwrapped { return decoder.decodeString() }
                catchingUnwrapped { return decoder.decodeLong() }
                catchingUnwrapped { return decoder.decodeDouble() }
                catchingUnwrapped { return decoder.decodeBoolean() }

                error("Could not decode param '$currentKey' for system '$systemName'")
            }

        }
    }
}