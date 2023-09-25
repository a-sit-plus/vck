package at.asitplus.wallet.lib.data

import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * SD-JWT representation of a [VerifiableCredential].
 */
@Serializable
data class VerifiableCredentialSdJwt(
    @SerialName("vc")
    val vc: VerifiableCredential,
    @SerialName("sub")
    val subject: String,
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant,
    @SerialName("iss")
    val issuer: String,
    @SerialName("exp")
    @Serializable(with = NullableInstantLongSerializer::class)
    val expiration: Instant?,
    @SerialName("jti")
    val jwtId: String,
    @SerialName("_sd")
    val selectiveDisclosures: List<SelectiveDisclosureItem>,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VerifiableCredentialSdJwt

        if (vc != other.vc) return false
        if (subject != other.subject) return false
        if (notBefore != other.notBefore) return false
        if (issuer != other.issuer) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false
        if (selectiveDisclosures != other.selectiveDisclosures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = vc.hashCode()
        result = 31 * result + subject.hashCode()
        result = 31 * result + notBefore.hashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + jwtId.hashCode()
        result = 31 * result + selectiveDisclosures.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<VerifiableCredentialSdJwt>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}