package at.asitplus.openid.jwtpayload.claims

import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlin.time.Instant

/**
 * Defined in [draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-10)
 * Section 5.1
 */
interface ClientAttestationPopClaims : JwtPayload {
    override val audience: String
    override val jwtId: String
    override val issuedAt: Instant
    val challenge: String?

    /**
     * OID4VCI: OPTIONAL (string).
     * The value type of this claim MUST be a string, where the value is a server-provided c_nonce.
     * It MUST be present when the issuer has a Nonce Endpoint as defined in Section 7.
     */
    val nonce: String?
}
