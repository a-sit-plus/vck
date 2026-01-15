package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = DCQLAuthorityKeyIdentifierInlineStringSerializer::class)
data class DCQLAuthorityKeyIdentifier(
    val byteArray: ByteArray
) {
    constructor(string: String) : this(
        string.decodeToByteArray(Base64.UrlSafe)
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DCQLAuthorityKeyIdentifier

        if (!byteArray.contentEquals(other.byteArray)) return false

        return true
    }

    override fun hashCode(): Int {
        return byteArray.contentHashCode()
    }
}

class DCQLAuthorityKeyIdentifierInlineStringSerializer : KSerializer<DCQLAuthorityKeyIdentifier> {
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            serialName = DCQLAuthorityKeyIdentifierInlineStringSerializer::class.qualifiedName!!,
            original = ByteArrayBase64UrlSerializer.descriptor,
        )

    override fun serialize(
        encoder: Encoder,
        value: DCQLAuthorityKeyIdentifier
    ) {
        encoder.encodeSerializableValue(
            ByteArrayBase64UrlSerializer,
            value.byteArray
        )
    }

    override fun deserialize(decoder: Decoder) = DCQLAuthorityKeyIdentifier(
        decoder.decodeSerializableValue(
            ByteArrayBase64UrlSerializer,
        )
    )
}