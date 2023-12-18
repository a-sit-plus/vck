package at.asitplus.wallet.lib.data

import at.asitplus.crypto.datatypes.jws.JsonWebKey
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
    val disclosureDigests: List<String>,
    @SerialName("type")
    val type: Array<String>,
    @SerialName("credentialStatus")
    val credentialStatus: CredentialStatus? = null,
    @SerialName("_sd_alg")
    val selectiveDisclosureAlgorithm: String,
    @SerialName("cnf")
    val confirmationKey: JsonWebKey? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as VerifiableCredentialSdJwt

        if (subject != other.subject) return false
        if (notBefore != other.notBefore) return false
        if (issuer != other.issuer) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false
        if (disclosureDigests != other.disclosureDigests) return false
        if (!type.contentEquals(other.type)) return false
        if (credentialStatus != other.credentialStatus) return false
        if (selectiveDisclosureAlgorithm != other.selectiveDisclosureAlgorithm) return false
        if (confirmationKey != other.confirmationKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = subject.hashCode()
        result = 31 * result + notBefore.hashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + jwtId.hashCode()
        result = 31 * result + disclosureDigests.hashCode()
        result = 31 * result + type.contentHashCode()
        result = 31 * result + (credentialStatus?.hashCode() ?: 0)
        result = 31 * result + selectiveDisclosureAlgorithm.hashCode()
        result = 31 * result + (confirmationKey?.hashCode() ?: 0)
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