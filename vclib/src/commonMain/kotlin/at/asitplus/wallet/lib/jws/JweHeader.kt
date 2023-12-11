package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

/**
 * Header of a [JweEncrypted] or [JweDecrypted].
 */
@Serializable
data class JweHeader(
    @SerialName("alg")
    val algorithm: JweAlgorithm?,
    @SerialName("enc")
    val encryption: JweEncryption?,
    @SerialName("kid")
    val keyId: String,
    @SerialName("typ")
    val type: JwsContentType?,
    @SerialName("cty")
    val contentType: JwsContentType? = null,
    @SerialName("epk")
    val ephemeralKeyPair: JsonWebKey? = null,
    @SerialName("apu")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyUInfo: ByteArray? = null,
    @SerialName("apv")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val agreementPartyVInfo: ByteArray? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JweHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}