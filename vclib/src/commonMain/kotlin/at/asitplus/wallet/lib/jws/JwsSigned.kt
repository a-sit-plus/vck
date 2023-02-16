package at.asitplus.wallet.lib.jws

import io.matthewnelson.component.base64.Base64
import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64
import io.github.aakira.napier.Napier

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
        return "${plainSignatureInput}.${signature.encodeBase64(Base64.UrlSafe(pad = false))}"
    }

    companion object {
        fun parse(it: String): JwsSigned? {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 3) return null.also { Napier.w("Could not parse JWS: $it") }
            val headerInput = stringList[0].decodeBase64ToArray()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val header = JwsHeader.deserialize(headerInput.decodeToString())
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val payload = stringList[1].decodeBase64ToArray()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            val signature = stringList[2].decodeBase64ToArray()
                ?: return null.also { Napier.w("Could not parse JWS: $it") }
            return JwsSigned(header, payload, signature, "${stringList[0]}.${stringList[1]}")
        }
    }
}