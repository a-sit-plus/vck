package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64Url
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@Serializable(with = CompactJsonWebSignatureSerializer::class)
data class CompactJsonWebSignature(
    val header: ByteArray,
    val payload: ByteArray,
    val signature: ByteArray,
) {
    init {
        validate(
            header = header,
            payload = payload,
            signature = signature,
        )
    }

    fun toFlattenedJsonWebSignature() = FlattenedJsonWebSignature(
        protected = header,
        payload = payload,
        signature = signature,
    )

    val signatureInput: ByteArray
        get() = "${header.decodeToString()}.${payload.decodeToString()}.${signature.decodeToString()}".encodeToByteArray()

    companion object {
        fun deserialize(input: String): CompactJsonWebSignature {
            val segments = input.split(".")
            if (segments.size != Specification.SEGMENT_COUNT) {
                throw IllegalArgumentException("Argument `input` must contain exactly two dots(`.`) when using JWS Compact Serialization.")
            }

            val (header, payload, signature) = segments

            return CompactJsonWebSignature(
                payload = payload.decodeBase64Url(),
                header = header.decodeBase64Url(),
                signature = signature.decodeBase64Url(),
            )
        }

        fun validate(
            header: ByteArray,
            payload: ByteArray,
            signature: ByteArray,
            json: Json = Json,
        ) {
            // header must be a valid json object
            json.decodeFromString<JsonObject>(header.decodeToString())
        }
    }

    object Specification {
        const val SEGMENT_COUNT = 3
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CompactJsonWebSignature

        if (!header.contentEquals(other.header)) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = header.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

