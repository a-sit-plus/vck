package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.jws.JsonWebKey
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
    val type: Collection<String>,
    @SerialName("credentialStatus")
    val credentialStatus: CredentialStatus? = null,
    @SerialName("_sd_alg")
    val selectiveDisclosureAlgorithm: String,
    @SerialName("cnf")
    val confirmationKey: JsonWebKey? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<VerifiableCredentialSdJwt>(it)
        }.wrap()
    }

}