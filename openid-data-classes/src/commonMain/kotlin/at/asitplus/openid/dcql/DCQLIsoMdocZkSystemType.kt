package at.asitplus.openid.dcql

import at.asitplus.iso.ZkRequest
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = DCQLIsoMdocZkSystemType.Companion.Serializer::class)
data class DCQLIsoMdocZkSystemType(
    val systemSpecs: List<DCQLIsoMdocZkSystemSpec>,

    @Transient
    val zkRequired: Boolean = false
) {
    fun toZkRequest() = ZkRequest(
        systemSpecs = systemSpecs.map { it.toZkSystemSpec() },
        zkRequired = zkRequired
    )

    fun validate() {
        // automatically validates in ZkRequest's init block
        toZkRequest()
    }

    companion object {
        object Serializer : KSerializer<DCQLIsoMdocZkSystemType> {
            private val delegate = ListSerializer(DCQLIsoMdocZkSystemSpec.serializer())

            override val descriptor = delegate.descriptor

            override fun serialize(encoder: Encoder, value: DCQLIsoMdocZkSystemType) {
                encoder.encodeSerializableValue(delegate, value.systemSpecs)
            }

            override fun deserialize(decoder: Decoder): DCQLIsoMdocZkSystemType {
                return DCQLIsoMdocZkSystemType(decoder.decodeSerializableValue(delegate))
            }
        }
    }
}



