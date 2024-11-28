package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CborSerializableCompressedStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.CborSerializableCompressedStatusList.Companion.toCborSerializableCompressedStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JsonSerializableCompressedTokenStatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal.JsonSerializableCompressedTokenStatusList.Companion.toJsonSerializableStatusList
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
@ExperimentalUnsignedTypes
object StatusListSerializer : KSerializer<StatusList> {
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            // TODO: how to properly write a serial descriptor for a polymorphic serializer?
            serialName = StatusList::class.qualifiedName!!,
            original = StatusListSurrogate.serializer().descriptor,
        )

    override fun deserialize(decoder: Decoder): StatusList {
        return when (decoder) {
            is JsonDecoder -> JsonSerializableCompressedTokenStatusList.serializer()
                .deserialize(decoder).toStatusListSurrogate()

            is CborDecoder -> CborSerializableCompressedStatusList.serializer().deserialize(decoder)
                .toStatusListSurrogate()

            else -> {
                Napier.w("Argument `decoder` uses an experimental format, results may be incorrect. Supported Formats: [${
                    listOf(
                        Json::class,
                        Cbor::class,
                    ).joinToString(",") {
                        it.qualifiedName!!
                    }
                }]")

                StatusListSurrogate.serializer().deserialize(decoder)
            }
        }.toStatusList()
    }

    override fun serialize(encoder: Encoder, value: StatusList) {
        when (encoder) {
            is JsonEncoder -> JsonSerializableCompressedTokenStatusList.serializer()
                .serialize(encoder, value.toStatusListSurrogate().toJsonSerializableStatusList())

            is CborEncoder -> CborSerializableCompressedStatusList.serializer()
                .serialize(encoder, value.toStatusListSurrogate().toCborSerializableCompressedStatusList())


            else -> {
                Napier.w("Argument `encoder` uses an experimental format, results may be incorrect. Supported Formats: [${
                    listOf(
                        Json::class,
                        Cbor::class,
                    ).joinToString(",") {
                        it.qualifiedName!!
                    }
                }]")

                StatusListSurrogate.serializer().serialize(encoder, value.toStatusListSurrogate())
            }
        }
    }
}