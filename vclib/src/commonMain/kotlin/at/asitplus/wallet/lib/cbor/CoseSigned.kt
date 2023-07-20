package at.asitplus.wallet.lib.cbor

import at.asitplus.wallet.lib.iso.cborSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ByteStringWrapper
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Representation of a signed COSE_Sign1 object, i.e. consisting of protected header, unprotected header and payload.
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray(18U)
data class CoseSigned(
    @Serializable(with = ByteStringWrapperCoseHeaderSerializer::class)
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    val unprotectedHeader: CoseHeader? = null,
    @ByteString
    val payload: ByteArray? = null,
    @ByteString
    val signature: ByteArray,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSigned

        if (protectedHeader != other.protectedHeader) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEquals(other.payload)) return false
        } else if (other.payload != null) return false
        return signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = protectedHeader.hashCode()
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        result = 31 * result + signature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "CoseSigned(protectedHeader=${protectedHeader.value}," +
                " unprotectedHeader=$unprotectedHeader," +
                " payload=${payload?.encodeBase16()}," +
                " signature=${signature.encodeBase16()})"
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseSigned>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable
@CborArray
data class CoseSignatureInput(
    val contextString: String = "Signature1",
    @Serializable(with = ByteStringWrapperCoseHeaderSerializer::class)
    @ByteString
    val protectedHeader: ByteStringWrapper<CoseHeader>,
    @ByteString
    val externalAad: ByteArray = byteArrayOf(),
    @ByteString
    val payload: ByteArray? = null,
){
    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseSignatureInput

        if (contextString != other.contextString) return false
        if (protectedHeader != other.protectedHeader) return false
        if (!externalAad.contentEquals(other.externalAad)) return false
        if (payload != null) {
            if (other.payload == null) return false
            if (!payload.contentEquals(other.payload)) return false
        } else if (other.payload != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = contextString.hashCode()
        result = 31 * result + protectedHeader.hashCode()
        result = 31 * result + externalAad.contentHashCode()
        result = 31 * result + (payload?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseSignatureInput(contextString='$contextString'," +
                " protectedHeader=${protectedHeader.value}," +
                " externalAad=${externalAad.encodeBase16()}," +
                " payload=${payload?.encodeBase16()})"
    }


    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseSignatureInput>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}

object ByteStringWrapperCoseHeaderSerializer : KSerializer<ByteStringWrapper<CoseHeader>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("ByteStringWrapperCoseHeaderSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<CoseHeader>) {
        val bytes = cborSerializer.encodeToByteArray(value.value)
        encoder.encodeSerializableValue(ByteArraySerializer(), bytes)
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<CoseHeader> {
        val bytes = decoder.decodeSerializableValue(ByteArraySerializer())
        return ByteStringWrapper(cborSerializer.decodeFromByteArray(bytes), bytes)
    }

}
