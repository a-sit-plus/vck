package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Metadata about the credential issuer in
 * [SD-JWT VC](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-10.html#name-jwt-vc-issuer-metadata)
 *
 * Issuers publishing JWT VC Issuer Metadata MUST make a JWT VC Issuer Metadata configuration available at the location
 * formed by inserting the well-known string `/.well-known/jwt-vc-issuer` (see
 * [OpenIdConstants.PATH_WELL_KNOWN_JWT_VC_ISSUER_METADATA]) between the host component and the path component (if any)
 * of the `iss` claim value in the JWT. The iss MUST be a case-sensitive URL using the HTTPS scheme that contains
 * scheme, host and, optionally, port number and path components, but no query or fragment components.
 */
@Serializable
data class JwtVcIssuerMetadata(
    /**
     * REQUIRED. The Issuer identifier, which MUST be identical to the `iss` value in the JWT.
     */
    @SerialName("issuer")
    val issuer: String,

    /**
     * OPTIONAL. Issuer's JSON Web Key Set [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) document value,
     * which contains the Issuer's public keys.
     * The value of this field MUST be a JSON object containing a valid JWK Set.
     */
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet? = null,

    /**
     * OPTIONAL. URL string referencing the Issuer's JSON Web Key (JWK) Set
     * [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) document which contains the Issuer's public keys.
     * The value of this field MUST point to a valid JWK Set document.
     */
    @SerialName("jwks_uri")
    val jsonWebKeySetUrl: String? = null,
)