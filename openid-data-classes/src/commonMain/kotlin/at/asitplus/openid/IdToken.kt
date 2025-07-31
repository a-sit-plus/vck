package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlin.time.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OpenID Connect ID Token, usually signed as JWS in `id_token` in a URL
 */
@Serializable
data class IdToken(
    /**
     * OIDC: REQUIRED. Issuer Identifier for the Issuer of the response. The iss value is a case sensitive URL using the
     * https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment
     * components.
     *
     * OIDC SIOPv2: REQUIRED. in case of a Self-Issued ID Token, this claim MUST be set to the value of the `sub` claim
     * in the same ID Token.
     */
    @SerialName("iss")
    val issuer: String,

    /**
     * OIDC: REQUIRED. Audience(s) that this ID Token is intended for. It MUST contain the OAuth 2.0 `client_id` of the
     * Relying Party as an audience value. It MAY also contain identifiers for other audiences. In the general case, the
     * `aud` value is an array of case sensitive strings. In the common special case when there is one audience,
     * the `aud` value MAY be a single case sensitive string.
     */
    @SerialName("aud")
    val audience: String,

    /**
     * OIDC: REQUIRED. Time at which the JWT was issued. Its value is a JSON number representing the number of seconds
     * from 1970-01-01T0:0:0Z as measured in UTC until the date/time.
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,

    /**
     * OIDC: REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing. The
     * processing of this parameter requires that the current date/time MUST be before the expiration date/time listed
     * in the value. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for
     * clock skew. Its value is a JSON number representing the number of seconds from 1970-01-01T0:0:0Z as measured in
     * UTC until the date/time.
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant,

    /**
     * OIDC: REQUIRED. Subject Identifier. A locally unique and never reassigned identifier within the Issuer for the
     * End-User, which is intended to be consumed by the Client, e.g., `24400320`. It MUST NOT exceed 255 ASCII
     * characters in length. The sub value is a case sensitive string.
     *
     * OIDC SIOPv2: REQUIRED. Subject identifier value. When Subject Syntax Type is JWK Thumbprint, the value is the
     * base64url encoded representation of the thumbprint of the key in the `sub_jwk` Claim. When Subject Syntax Type is
     * Decentralized Identifier, the value is a Decentralized Identifier.
     */
    @SerialName("sub")
    val subject: String,

    /**
     * OIDC: String value used to associate a Client session with an ID Token, and to mitigate replay attacks. The value
     * is passed through unmodified from the Authentication Request to the ID Token. If present in the ID Token, Clients
     * MUST verify that the nonce Claim Value is equal to the value of the nonce parameter sent in the Authentication
     * Request. If present in the Authentication Request, Authorization Servers MUST include a nonce Claim in the ID
     * Token with the Claim Value being the nonce value sent in the Authentication Request. Authorization Servers SHOULD
     * perform no other processing on nonce values used. The nonce value is a case sensitive string.
     */
    @SerialName("nonce")
    val nonce: String,

    /**
     * OIDC SIOPv2: OPTIONAL. A JSON object that is a public key used to check the signature of an ID Token when
     * Subject Syntax Type is JWK Thumbprint. The key is a bare key in JWK (RFC7517) format (not an X.509 certificate
     * value). MUST NOT be present when Subject Syntax Type other than JWK Thumbprint is used.
     */
    @SerialName("sub_jwk")
    val subjectJwk: JsonWebKey? = null,
)