package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.KeyMaterial

/**
 * How a client authenticates with
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html):
 * the instance attestation loaded by [loadInstanceAttestation], and the [keyMaterial] it attests. Both belong together,
 * as the attestation MUST reference [keyMaterial] in its `cnf` claim, which [OAuth2ProtocolClient] checks before using
 * it.
 */
class ClientAttestation(
    /** The key the instance attestation attests, which signs the client attestation PoP (or the DPoP proof). */
    val keyMaterial: KeyMaterial,
    /**
     * Returns a new instance attestation, e.g. a Wallet Instance Attestation (WIA), for the authorization server.
     * The returned JWT MUST reference [keyMaterial] in [JsonWebToken.confirmationClaim].
     */
    val loadInstanceAttestation: suspend (OAuth2ProtocolClient.LoadInstanceAttestationInput) -> KmmResult<JwsCompactTyped<JsonWebToken>>,
)
