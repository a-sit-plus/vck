package at.asitplus.wallet.lib.oauth2

import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.jwtpayload.ClientAttestationClaims
import at.asitplus.signum.indispensable.josef.jwtpayload.WalletInstanceAttestationClaims
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
import kotlin.time.Instant


/**
 * Simple client authentication service for an OAuth2.0 AS.
 *
 * Implemented from:
 * * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-05.html)
 * * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
class ClientAuthenticationService @JvmOverloads constructor(
    /** Enforce client authentication as defined in OpenID4VC HAIP, i.e. with wallet attestations */
    private val enforceClientAuthentication: Boolean = false,
    /** Used to verify client attestation JWTs */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to verify client attestation JWTs */
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    /** Callback to verify the client attestation JWT against a set of trusted roots */
    private val verifyClientAttestationJwt: (suspend (JwsCompactTyped<ClientAttestationClaims>) -> Boolean) = { true },
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

    private fun JwsCompactTyped<ClientAttestationClaims.Attestation>.validateWalletInstanceAttestation(clientId: String?) {
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
        if (clientId != null && payload.subject != clientId) {
            throw InvalidClient("subject not equal to client_id")
        }
        val issuedAt = payload.issuedAt ?: throw InvalidClient("client attestation has no iat")
        if (issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidClient("client attestation iat in future: $issuedAt")
        }
        if (payload.expiration < (clock.now() - timeLeeway)) {
            throw InvalidClient("client attestation expired: ${payload.expiration}")
        }
        if (payload.expiration - issuedAt >= 24.hours) {
            throw InvalidClient("client attestation lifetime must be less than 24 hours")
        }
        with(payload as? WalletInstanceAttestationClaims) {
            validate(clock.now() - timeLeeway)
        }
    }

    private fun JwsCompactTyped<ClientAttestationClaims.ProofOfPossession>.validateWalletInstanceAttestationPop(clientId: String?) {
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
        if (payload.issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidClient("client attestation PoP iat in future: ${payload.issuedAt}")
        }
        if (payload.expiration == null || payload.expiration!! < (clock.now() - timeLeeway)) {
            throw InvalidClient("client attestation PoP expired: ${payload.expiration}")
        }

        //Previously missing?
        with(payload as? WalletInstanceAttestationClaims) {
            validate(clock.now() - timeLeeway)
        }
    }
}

//Currently we only support [WalletAttestationClaims], do we want to support more general [ClientAttestationClaims]?
/**
 * timeNow = Clock.now - leeway
 */
private fun WalletInstanceAttestationClaims?.validate(timeNow: Instant) {
    if (this == null) {
        throw InvalidClient("client attestation is not a valid WalletAttestationPayload")
    }
    if (walletName.isBlank()) {
        throw InvalidClient("client attestation has no wallet_name")
    }
    if (walletVersion.isBlank()) {
        throw InvalidClient("client attestation has no wallet_version")
    }
    if (walletSolutionCertificationInformation.isBlank()) {
        throw InvalidClient("client attestation has no wallet_solution_certification_information")
    }
    if (clientStatus.expiration < timeNow) {
        throw InvalidClient("client_status expiration in past: ${clientStatus.expiration}")
    }
}