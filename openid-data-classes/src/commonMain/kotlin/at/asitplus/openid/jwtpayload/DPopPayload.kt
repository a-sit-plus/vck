package at.asitplus.openid.jwtpayload

import at.asitplus.openid.HttpMethodSerializer
import at.asitplus.openid.jwtpayload.claims.DemonstratingProofOfPossessionClaims
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC9449
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant


/**
 * Defined in [RFC9449](https://www.rfc-editor.org/rfc/rfc9449.html) Sec 4.2
 */
@Serializable
data class DpopPayload(
    @SerialName(RFC7519.ISS)
    override val issuer: String? = null,

    @SerialName(RFC7519.SUB)
    override val subject: String? = null,

    @SerialName(RFC7519.AUD)
    override val audience: String? = null,

    @SerialName(RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,

    @SerialName(RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,

    @SerialName(RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant? = null,

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
    override val jwtId: String,

    /**
     * REQUIRED:
     * The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.
     */
    @SerialName(RFC9449.HTM)
    @Serializable(with = HttpMethodSerializer::class)
    override val httpMethod: HttpMethod,

    /**
     * REQUIRED:
     * The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached,
     * without query and fragment parts.
     */
    @SerialName(RFC9449.HTU)
    override val httpTargetUrl: Url,

    /**
     * REQUIRED*:
     * When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access
     * (see Section 7), the DPoP proof MUST also contain the following claim:
     * Hash of the access token. The value MUST be the result of a base64url encoding (as defined in
     * Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
    */
    @SerialName(RFC9449.ATH)
    override val accessTokenHash: String? = null,

    /**
     * REQUIRED*:
     * When the authentication server or resource server provides a DPoP-Nonce HTTP header in a response
     * (see Sections 8 and 9), the DPoP proof MUST also contain the following claim
    */
    @SerialName(RFC9449.NONCE)
    override val nonce: String? = null
) : DemonstratingProofOfPossessionClaims
