package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CborSerializableCompressedStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CborSerializableCompressedStatusList.Companion.toCborSerializableCompressedStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JsonSerializableCompressedTokenStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JsonSerializableCompressedTokenStatusList.Companion.toJsonSerializableCompressedTokenStatusList
import io.github.aakira.napier.Napier
import kotlinx.serialization.KSerializer
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder

/**
 * Workaround to support serialization without type discriminator and format-specific serialization.
 */
object StatusListSerializer : KSerializer<StatusList> {
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            // TODO: how to properly write a serial descriptor for a polymorphic serializer?
            serialName = StatusList::class.qualifiedName!!,
            original = CompressedStatusList.serializer().descriptor,
        )

    override fun deserialize(decoder: Decoder): StatusList {
        return when (decoder) {
            is JsonDecoder -> JsonSerializableCompressedTokenStatusList.serializer()
                .deserialize(decoder).toCompressedStatusList()

            is CborDecoder -> CborSerializableCompressedStatusList.serializer().deserialize(decoder)
                .toCompressedStatusList()

            else -> {
                Napier.w("Argument `decoder` uses an unsupported format, results may be incorrect. Supported Formats: [${
                    listOf(
                        Json::class,
                        Cbor::class,
                    ).joinToString(",") {
                        it.qualifiedName!!
                    }
                }]")

                CompressedStatusList.serializer().deserialize(decoder)
            }
        }.decompress()
    }

    override fun serialize(encoder: Encoder, value: StatusList) {
        when (encoder) {
            is JsonEncoder -> JsonSerializableCompressedTokenStatusList.serializer()
                .serialize(encoder, value.compress().toJsonSerializableCompressedTokenStatusList())

            is CborEncoder -> CborSerializableCompressedStatusList.serializer()
                .serialize(encoder, value.compress().toCborSerializableCompressedStatusList())


            else -> {
                Napier.w("Argument `encoder` uses an unsupported format, results may be incorrect. Supported Formats: [${
                    listOf(
                        Json::class,
                        Cbor::class,
                    ).joinToString(",") {
                        it.qualifiedName!!
                    }
                }]")

                CompressedStatusList.serializer().serialize(encoder, value.compress())
            }
        }
    }
}