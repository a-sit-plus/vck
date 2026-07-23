package at.asitplus.wallet.lib.oauth2

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames
import at.asitplus.signum.indispensable.josef.JwtPayload
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Defined in [RFC9449](https://www.rfc-editor.org/rfc/rfc9449.html) Sec 4.2
 * Additional claims MAY be included
 */
//TODO maybe Dpop interface?
data class DpopPayload(
    @SerialName(ClaimNames.RFC7519.ISS)
    override val issuer: String? = null,

    @SerialName(ClaimNames.RFC7519.SUB)
    override val subject: String? = null,

    @SerialName(ClaimNames.RFC7519.AUD)
    override val audience: String? = null,

    @SerialName(ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant? = null,

    @SerialName(ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant,

    @SerialName(ClaimNames.RFC7519.EXP)
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
    @SerialName(ClaimNames.RFC7519.JTI)
    override val jwtId: String,

    /**
     * REQUIRED:
     * The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.
     */
    @SerialName(ClaimNames.RFC9449.HTM)
    val httpMethod: HttpMethod,

    /**
     * REQUIRED:
     * The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached,
     * without query and fragment parts.
     */
    @SerialName(ClaimNames.RFC9449.HTU)
    val httpTarget: Url,

    /**
     * REQUIRED*:
     * When the DPoP proof is used in conjunction with the presentation of an access token in protected resource access
     * (see Section 7), the DPoP proof MUST also contain the following claim:
     * Hash of the access token. The value MUST be the result of a base64url encoding (as defined in
     * Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.
     */
    @SerialName(ClaimNames.RFC9449.ATH)
    @Serializable(with = ByteArrayBase64Serializer::class)
    val accessTokenHash: ByteArray? = null,
) : JwtPayload {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DpopPayload

        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (audience != other.audience) return false
        if (notBefore != other.notBefore) return false
        if (issuedAt != other.issuedAt) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false
        if (httpMethod != other.httpMethod) return false
        if (httpTarget != other.httpTarget) return false
        if (!accessTokenHash.contentEquals(other.accessTokenHash)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuer?.hashCode() ?: 0
        result = 31 * result + (subject?.hashCode() ?: 0)
        result = 31 * result + (audience?.hashCode() ?: 0)
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + issuedAt.hashCode()
        result = 31 * result + (expiration?.hashCode() ?: 0)
        result = 31 * result + jwtId.hashCode()
        result = 31 * result + httpMethod.hashCode()
        result = 31 * result + httpTarget.hashCode()
        result = 31 * result + (accessTokenHash?.contentHashCode() ?: 0)
        return result
    }
}