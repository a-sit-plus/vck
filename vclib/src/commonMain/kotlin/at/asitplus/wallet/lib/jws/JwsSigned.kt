package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.Base64Strict
import at.asitplus.wallet.lib.data.Base64UrlStrict
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Representation of a signed JSON Web Signature object, i.e. consisting of header, payload and signature.
 */
data class JwsSigned(
    val header: JwsHeader,
    val payload: ByteArray,
    val signature: ByteArray,
    val plainSignatureInput: String,
) {
    fun serialize(): String {
        return "${plainSignatureInput}.${signature.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsSigned

        if (header != other.header) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false
        return plainSignatureInput == other.plainSignatureInput
    }

    override fun hashCode(): Int {
        var result = header.hashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + plainSignatureInput.hashCode()
        return result
    }

    companion object {
        fun parse(input: String): JwsSigned? {
            val stringList = input.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) return null.also { Napier.w("Could not parse JWS: $input") }
            val headerInput = stringList[0].decodeToByteArrayOrNull(Base64Strict)
                ?: return null.also { Napier.w("Could not parse JWS: $input") }
            val header = JwsHeader.deserialize(headerInput.decodeToString())
                ?: return null.also { Napier.w("Could not parse JWS: $input") }
            val payload = stringList[1].decodeToByteArrayOrNull(Base64Strict)
                ?: return null.also { Napier.w("Could not parse JWS: $input") }
            val signature = stringList[2].decodeToByteArrayOrNull(Base64Strict)
                ?: return null.also { Napier.w("Could not parse JWS: $input") }
            return JwsSigned(header, payload, signature, "${stringList[0]}.${stringList[1]}")
        }
    }
}