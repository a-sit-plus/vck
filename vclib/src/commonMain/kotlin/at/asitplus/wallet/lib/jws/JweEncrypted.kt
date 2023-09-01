package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.Base64Url
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Representation of an encrypted JSON Web Encryption object, consisting of its 5 parts: Header, encrypted key,
 * IV, ciphertext, authentication tag.
 *
 * @see [JweDecrypted]
 */
data class JweEncrypted(
    val headerAsParsed: ByteArray,
    val encryptedKey: ByteArray? = null,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val authTag: ByteArray
) {
    val header: JweHeader?
        get() = JweHeader.deserialize(headerAsParsed.decodeToString())

    fun serialize(): String {
        return headerAsParsed.encodeToString(Base64Url) +
                ".${encryptedKey?.encodeToString(Base64Url) ?: ""}" +
                ".${iv.encodeToString(Base64Url)}" +
                ".${ciphertext.encodeToString(Base64Url)}" +
                ".${authTag.encodeToString(Base64Url)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweEncrypted

        if (!headerAsParsed.contentEquals(other.headerAsParsed)) return false
        if (encryptedKey != null) {
            if (other.encryptedKey == null) return false
            if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        } else if (other.encryptedKey != null) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authTag.contentEquals(other.authTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = headerAsParsed.contentHashCode()
        result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + authTag.contentHashCode()
        return result
    }


    companion object {
        fun parse(it: String): JweEncrypted? {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 5) return null.also { Napier.w("Could not parse JWE: $it") }
            val headerAsParsed = stringList[0].decodeToByteArrayOrNull(Base64(strict = true))
                ?: return null.also { Napier.w("Could not parse JWE: $it") }
            val encryptedKey = stringList[1].decodeToByteArrayOrNull(Base64(strict = true))
            val iv = stringList[2].decodeToByteArrayOrNull(Base64(strict = true))
                ?: return null.also { Napier.w("Could not parse JWE: $it") }
            val ciphertext = stringList[3].decodeToByteArrayOrNull(Base64(strict = true))
                ?: return null.also { Napier.w("Could not parse JWE: $it") }
            val authTag = stringList[4].decodeToByteArrayOrNull(Base64(strict = true))
                ?: return null.also { Napier.w("Could not parse JWE: $it") }
            return JweEncrypted(headerAsParsed, encryptedKey, iv, ciphertext, authTag)
        }
    }
}