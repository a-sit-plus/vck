package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidClient
import kotlin.coroutines.cancellation.CancellationException


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
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to verify client attestation JWTs */
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    /** Callback to verify the client attestation JWT against a set of trusted roots */
    private val verifyClientAttestationJwt: (suspend (JwsCompactTyped<JsonWebToken>) -> Boolean) = { true },
) {

    /**
     * Authenticates the client as defined in OpenID4VC HAIP, i.e. with client attestation JWT.
     * Throws an exception if authentication fails. Honors [enforceClientAuthentication].
     */
    @Throws(InvalidClient::class, CancellationException::class)
    suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?,
    ) {
        // Enforce client authentication once all clients implement it
        if (enforceClientAuthentication) {
            if (httpRequest?.clientAttestation == null || httpRequest.clientAttestationPop == null) {
                throw InvalidClient("client attestation headers missing")
            }
        }

        if (httpRequest?.clientAttestation != null && httpRequest.clientAttestationPop != null) {
            val instanceAttestation = catching { JwsCompactTyped<JsonWebToken>(httpRequest.clientAttestation) }
                .getOrElse { throw InvalidClient("could not parse instance attestation", it) }

            verifyJwsObject(instanceAttestation.jws).getOrElse {
                throw InvalidClient("client attestation JWT not verified", it)
            }
            if (clientId != null) {
                if (instanceAttestation.payload.subject != clientId) {
                    throw InvalidClient("subject not equal to client_id")
                }
            }

            if (!verifyClientAttestationJwt.invoke(instanceAttestation)) {
                throw InvalidClient("client attestation not verified")
            }

            val instanceAttestationPopJwt = catching {
                JwsCompactTyped<JsonWebToken>(httpRequest.clientAttestationPop)
            }.getOrElse {
                throw InvalidClient("could not parse client attestation PoP", it)
            }
            val cnf = instanceAttestation.payload.confirmationClaim
                ?: throw InvalidClient("client attestation has no cnf")
            if (!verifyJwsSignatureWithCnf(instanceAttestationPopJwt.jws, cnf)) {
                throw InvalidClient("client attestation PoP JWT not verified")
            }
        }
    }

}
