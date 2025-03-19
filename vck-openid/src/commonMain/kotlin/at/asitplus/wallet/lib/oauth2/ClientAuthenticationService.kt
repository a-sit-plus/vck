package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.*
import io.github.aakira.napier.Napier
import kotlin.String


/**
 * Simple client authentication service for an OAuth2.0 AS.
 *
 * Implemented from
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html)
 */
class ClientAuthenticationService(
    /** Enforce client authentication as defined in OpenID4VC HAIP, i.e. with wallet attestations */
    private val enforceClientAuthentication: Boolean = false,
    /** Used to verify client attestation JWTs */
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    /** Callback to verify the client attestation JWT against a set of trusted roots */
    private val verifyClientAttestationJwt: (suspend (JwsSigned<JsonWebToken>) -> Boolean) = { true },
) {

    /**
     * Authenticates the client as defined in OpenID4VC HAIP, i.e. with client attestation JWT
     */
    suspend fun authenticateClient(
        clientAttestation: String?,
        clientAttestationPop: String?,
        clientId: String?,
    ) {
        // Enforce client authentication once all clients implement it
        if (enforceClientAuthentication) {
            if (clientAttestation == null || clientAttestationPop == null) {
                Napier.w("auth: client not sent client attestation")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation headers missing")
            }
        }
        if (clientAttestation != null && clientAttestationPop != null) {
            val clientAttestationJwt = JwsSigned
                .deserialize<JsonWebToken>(JsonWebToken.serializer(), clientAttestation, vckJsonSerializer)
                .getOrElse {
                    Napier.w("auth: could not parse client attestation JWT", it)
                    throw OAuth2Exception(Errors.INVALID_CLIENT, "could not parse client attestation", it)
                }
            if (!verifierJwsService.verifyJwsObject(clientAttestationJwt)) {
                Napier.w("auth: client attestation JWT not verified")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation JWT not verified")
            }
            if (clientAttestationJwt.payload.subject != clientId) {
                Napier.w("auth: subject ${clientAttestationJwt.payload.subject} not matching client_id $clientId")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "subject not equal to client_id")
            }

            if (!verifyClientAttestationJwt.invoke(clientAttestationJwt)) {
                Napier.w("auth: client attestation not verified by callback: $clientAttestationJwt")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation not verified")
            }

            val clientAttestationPopJwt = JwsSigned
                .deserialize<JsonWebToken>(JsonWebToken.serializer(), clientAttestationPop, vckJsonSerializer)
                .getOrElse {
                    Napier.w("auth: could not parse client attestation PoP JWT", it)
                    throw OAuth2Exception(Errors.INVALID_CLIENT, "could not parse client attestation PoP", it)
                }
            val cnf = clientAttestationJwt.payload.confirmationClaim
                ?: throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation has no cnf")
            if (!verifierJwsService.verifyJws(clientAttestationPopJwt, cnf)) {
                Napier.w("auth: client attestation PoP JWT not verified")
                throw OAuth2Exception(Errors.INVALID_CLIENT, "client attestation PoP JWT not verified")
            }
        }
    }

}
