package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.jsonSerializer
import at.asitplus.wallet.lib.jws.JsonWebKey
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

@Serializable
data class RelyingPartyMetadata(
    @SerialName("redirect_uris")
    val redirectUris: Array<String>,
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet,
    @SerialName("subject_syntax_types_supported")
    val subjectSyntaxTypesSupported: Array<String>,
    @SerialName("vp_formats")
    val vpFormats: FormatHolder? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as RelyingPartyMetadata

        if (!redirectUris.contentEquals(other.redirectUris)) return false
        if (jsonWebKeySet != other.jsonWebKeySet) return false
        if (!subjectSyntaxTypesSupported.contentEquals(other.subjectSyntaxTypesSupported)) return false
        if (vpFormats != other.vpFormats) return false

        return true
    }

    override fun hashCode(): Int {
        var result = redirectUris.contentHashCode()
        result = 31 * result + jsonWebKeySet.hashCode()
        result = 31 * result + subjectSyntaxTypesSupported.contentHashCode()
        result = 31 * result + (vpFormats?.hashCode() ?: 0)
        return result
    }


    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RelyingPartyMetadata>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}


@Serializable
data class JsonWebKeySet(
    @SerialName("keys")
    val keys: Array<JsonWebKey>,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebKeySet

        if (!keys.contentEquals(other.keys)) return false

        return true
    }

    override fun hashCode(): Int {
        return keys.contentHashCode()
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RelyingPartyMetadata>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}
