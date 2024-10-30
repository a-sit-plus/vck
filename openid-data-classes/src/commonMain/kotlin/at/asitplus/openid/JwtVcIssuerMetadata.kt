package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Metadata about the credential issuer in
 * [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-05.html)
 *
 * To be serialized into JSON and made available at `/.well-known/jwt-vc-issuer` at the credential issuer.
 */
@Serializable
data class JwtVcIssuerMetadata(
    /**
     * REQUIRED. The Issuer identifier, which MUST be identical to the `iss` value in the JWT.
     */
    @SerialName("issuer")
    val issuer: String,

    /**
     * OPTIONAL. Issuer's JSON Web Key Set (RFC7517) document value, which contains the Issuer's public keys.
     * The value of this field MUST be a JSON object containing a valid JWK Set.
     */
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet? = null,

    /**
     * OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set (RFC7517) document which contains the
     * Issuer's public keys. The value of this field MUST point to a valid JWK Set document.
     */
    @SerialName("jwks_uri")
    val jsonWebKeySetUrl: String? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<JwtVcIssuerMetadata> =
            runCatching { jsonSerializer.decodeFromString<JwtVcIssuerMetadata>(input) }.wrap()
    }
}