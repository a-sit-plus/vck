package at.asitplus.wallet.lib.jws

import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base64.Base64
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
        return "${plainSignatureInput}.${signature.encodeToString(Base64UrlNoPad)}"
    }

    companion object {
        fun parse(it: String): JwsSigned? {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) return null.also { Napier.w("Could not parse JWS: $it") }
            val headerInput = stringList[0].decodeBase64()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val header = JwsHeader.deserialize(headerInput.decodeToString())
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val payload = stringList[1].decodeBase64()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val signature = stringList[2].decodeBase64()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            return JwsSigned(header, payload, signature, "${stringList[0]}.${stringList[1]}")
        }
    }
}