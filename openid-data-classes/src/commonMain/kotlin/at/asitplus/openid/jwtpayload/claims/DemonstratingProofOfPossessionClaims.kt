package at.asitplus.openid.jwtpayload.claims

import at.asitplus.openid.HttpMethodSerializer
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC9449
import at.asitplus.signum.indispensable.josef.JwtPayload
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * [RFC9449](https://www.rfc-editor.org/rfc/rfc9449.html)
 * describes a mechanism for sender-constraining OAuth 2.0 tokens via a proof-of-possession mechanism
 * on the application level. This mechanism allows for the detection of replay attacks with access and refresh tokens.
 *
 * Not to be confused with [ProofOfPossessionClaims]
 *
 * May be used instead of [ClientAttestationPopClaims]
 * See [Section 5.2](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)
 */
interface DemonstratingProofOfPossessionClaims : JwtPayload {
    @SerialName(RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant

    /**
     * REQUIRED:
     * Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible
     * probability that the same value will be assigned to any other DPoP proof used in the same context during
     * the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other
     * suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 Universally Unique
     * Identifier (UUID) string according to [RFC4122]. The jti can be used by the server for replay detection
     * and prevention; see Section 11.1.
     */
    @SerialName(RFC7519.JTI)
    override val jwtId: String

    /**
     * REQUIRED:
     * The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.
     */
    @SerialName(RFC9449.HTM)
    @Serializable(with = HttpMethodSerializer::class)
    val httpMethod: HttpMethod

    /**
     * REQUIRED:
     * The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached,
     * without query and fragment parts.
     */
    @SerialName(RFC9449.HTU)
    val httpTargetUrl: Url

    /**
     * REQUIRED*:
     * When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access
     * (see Section 7), the DPoP proof MUST also contain the following claim:
     * Hash of the access token. The value MUST be the result of a base64url encoding (as defined in
     * Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
     */
    @SerialName(RFC9449.ATH)
    @Serializable(with = ByteArrayBase64Serializer::class)
    val accessTokenHash: String?

    /**
     * REQUIRED*:
     * When the authentication server or resource server provides a DPoP-Nonce HTTP header in a response
     * (see Sections 8 and 9), the DPoP proof MUST also contain the following claim
     */
    @SerialName(RFC9449.NONCE)
    val nonce: String?
}

