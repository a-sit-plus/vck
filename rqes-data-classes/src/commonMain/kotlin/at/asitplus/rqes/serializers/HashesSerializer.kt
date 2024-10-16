package at.asitplus.rqes.serializers

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * CSC: Multiple hash values can be passed as comma separated values,
 * e.g. oauth2/authorize?hash=dnN3ZX.. .ZmRm,ZjIxM3… Z2Zk,…
 */
object HashesSerializer : KSerializer<List<ByteArray>> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("HashesSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): List<ByteArray> {
        val listOfHashes = decoder.decodeString().split(",")
        return listOfHashes.map { at.asitplus.dif.jsonSerializer.decodeFromString(ByteArrayBase64UrlSerializer, it) }
    }

    override fun serialize(encoder: Encoder, value: List<ByteArray>) {
        val listOfHashes = value.map { at.asitplus.dif.jsonSerializer.encodeToString(ByteArrayBase64UrlSerializer, it) }
        encoder.encodeString(listOfHashes.joinToString(","))
    }
}