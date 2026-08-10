package at.asitplus.wallet.lib.oauth2

import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidClient
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes


/**
 * Simple client authentication service for an OAuth2.0 AS.
 *
 * Implemented from:
 * * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 * * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
class ClientAuthenticationService @JvmOverloads constructor(
    /** Enforce client authentication as defined in OpenID4VC HAIP, i.e. with wallet attestations */
    private val enforceClientAuthentication: Boolean = false,
    /**
     * Used to verify client attestation JWTs. Client attestations are required to carry an `x5c`, so pass
     * [at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate] with the certificates of the trusted wallet
     * providers to establish trust in the attestation. The default only verifies the attestation against the
     * certificate it carries itself, i.e. it makes no trust decision.
     */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to verify client attestation JWTs */
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    @Deprecated(
        "Pass VerifyJwsObjectTrustedCertificate with the trusted wallet provider certificates as " +
                "verifyJwsObject instead, which evaluates the x5c of the attestation against them."
    )
    /** Callback to verify the client attestation JWT against a set of trusted roots */
    private val verifyClientAttestationJwt: (suspend (JwsCompactTyped<JsonWebToken>) -> Boolean) = { true },
    /** Clock used to verify WIA and WIA PoP timestamps. */
    private val clock: Clock = Clock.System,
    /** Time leeway for verification of WIA and WIA PoP timestamps. */
    private val timeLeeway: Duration = 5.minutes,
    /**
     * The RFC 8414 issuer identifier of this authorization server.
     * When set, the `aud` claim of incoming WIA PoP JWTs is validated against this value.
     */
    private val issuerIdentifier: String? = null,
) {

    // TODO Add challenge service here

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
            val instanceAttestation = httpRequest.clientAttestation
            instanceAttestation.validateWalletInstanceAttestation(clientId)
            verifyJwsObject(instanceAttestation.jws).getOrElse {
                throw InvalidClient("client attestation JWT not verified", it)
            }

            @Suppress("DEPRECATION")
            if (!verifyClientAttestationJwt.invoke(instanceAttestation)) {
                throw InvalidClient("client attestation not verified")
            }

            val instanceAttestationPopJwt = httpRequest.clientAttestationPop
            instanceAttestationPopJwt.validateWalletInstanceAttestationPop(instanceAttestation.payload.subject)
            val cnf = instanceAttestation.payload.confirmationClaim
                ?: throw InvalidClient("client attestation has no cnf")
            if (!verifyJwsSignatureWithCnf(instanceAttestationPopJwt.jws, cnf)) {
                throw InvalidClient("client attestation PoP JWT not verified")
            }
        }
    }

    private fun JwsCompactTyped<JsonWebToken>.validateWalletInstanceAttestation(clientId: String?) {
        if (jws.jwsHeader.type != JwsContentTypeConstants.CLIENT_ATTESTATION_JWT) {
            throw InvalidClient("invalid client attestation typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.certificateChain.isNullOrEmpty()) {
            throw InvalidClient("client attestation has no x5c")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
            jws.jwsHeader.algorithm !in SimpleAuthorizationService.DEFAULT_WALLET_ATTESTATION_ALGORITHMS
        ) {
            throw InvalidClient("unsupported client attestation alg: ${jws.jwsHeader.algorithm}")
        }
        if (payload.issuer != null) {
            throw InvalidClient("client attestation must not contain iss")
        }
        if (payload.subject == null) {
            throw InvalidClient("client attestation has no sub")
        }
        if (clientId != null && payload.subject != clientId) {
            throw InvalidClient("subject not equal to client_id")
        }
        val issuedAt = payload.issuedAt ?: throw InvalidClient("client attestation has no iat")
        val expiration = payload.expiration ?: throw InvalidClient("client attestation has no exp")
        if (issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidClient("client attestation iat in future: $issuedAt")
        }
        if (expiration < (clock.now() - timeLeeway)) {
            throw InvalidClient("client attestation expired: $expiration")
        }
        if (expiration - issuedAt >= 24.hours) {
            throw InvalidClient("client attestation lifetime must be less than 24 hours")
        }
        if (payload.walletName.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_name")
        }
        if (payload.walletVersion.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_version")
        }
        if (payload.walletSolutionCertificationInformation.isNullOrBlank()) {
            throw InvalidClient("client attestation has no wallet_solution_certification_information")
        }
        val clientStatus = payload.clientStatus ?: throw InvalidClient("client attestation has no client_status")
        if (clientStatus.expiration < (clock.now() - timeLeeway)) {
            throw InvalidClient("client_status expiration in past: ${clientStatus.expiration}")
        }
        if (payload.confirmationClaim == null) {
            // TODO Validate this is an asymmetric key
            throw InvalidClient("client attestation has no cnf")
        }
    }

    private fun JwsCompactTyped<JsonWebToken>.validateWalletInstanceAttestationPop(clientId: String?) {
        if (jws.jwsHeader.type != JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT) {
            throw InvalidClient("invalid client attestation PoP typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
            jws.jwsHeader.algorithm !in SimpleAuthorizationService.DEFAULT_WALLET_ATTESTATION_ALGORITHMS
        ) {
            throw InvalidClient("unsupported client attestation PoP alg: ${jws.jwsHeader.algorithm}")
        }
        if (payload.issuer == null || payload.issuer != clientId) {
            throw InvalidClient("client attestation PoP iss not equal to client_id")
        }
        if (issuerIdentifier != null && payload.audience != issuerIdentifier) {
            throw InvalidClient(
                "client attestation PoP aud '${payload.audience}' does not match issuer '$issuerIdentifier'"
            )
        }
        if (payload.issuedAt == null || payload.issuedAt!! > (clock.now() + timeLeeway)) {
            throw InvalidClient("client attestation PoP iat in future: ${payload.issuedAt}")
        }
        if (payload.expiration == null || payload.expiration!! < (clock.now() - timeLeeway)) {
            throw InvalidClient("client attestation PoP expired: ${payload.expiration}")
        }
        // TODO Verify other fields
        // TODO Need to verify challenge
        // TODO Validate signature against CNF key
    }

}
