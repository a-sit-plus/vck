package at.asitplus.wallet.lib.jws

import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object ByteArrayBase64Serializer : KSerializer<ByteArray> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteArrayBase64Serializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteArray) {
        encoder.encodeString(value.encodeToString(Base64()))
    }

    override fun deserialize(decoder: Decoder): ByteArray {
        return decoder.decodeString().decodeToByteArrayOrNull(Base64()) ?: byteArrayOf()
    }

}