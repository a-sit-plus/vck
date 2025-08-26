package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable
data class OpenId4VciAccessToken(
    @SerialName("iss")
    val issuer: String? = null,

    @SerialName("aud")
    val audience: String? = null,

    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    @SerialName("jti")
    val jwtId: String? = null,

    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @SerialName("cnf")
    val confirmationClaim: ConfirmationClaim? = null,

    /** Scope that has been validated to use for credential issuance. */
    @SerialName("scope")
    val scope: String? = null,

    /** Authorization details that have been validated to use for credential issuance. */
    @SerialName("authorization_details")
    val authorizationDetails: Set<AuthorizationDetails>? = null,
)
