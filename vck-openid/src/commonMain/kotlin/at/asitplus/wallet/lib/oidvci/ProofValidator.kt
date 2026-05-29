package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKey
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKeyFun
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidProof
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class ProofValidator(
    /** Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients. */
    internal val publicContext: String = "https://wallet.a-sit.at/credential-issuer",
    /** Used to verify the signature of proof elements in credential requests. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Used to verify JWT proof signatures against keys attested by Key Attestations. */
    private val verifyJwsSignatureWithKey: VerifyJwsSignatureWithKeyFun = VerifyJwsSignatureWithKey(),
    /** Supported signing algorithms, which may be used from clients in proofs to request credentials. */
    private val supportedAlgorithms: Collection<JwsAlgorithm.Signature> =
        SimpleAuthorizationService.DEFAULT_WALLET_ATTESTATION_ALGORITHMS,
    /** Clock used to verify timestamps in proof elements in credential requests. */
    private val clock: Clock = Clock.System,
    /** Time leeway for verification of timestamps in proof elements in credential requests. */
    private val timeLeeway: Duration = 5.minutes,
    /** Callback to verify a received [KeyAttestationJwt] proof in credential requests. */
    private val verifyAttestationProof: suspend (JwsCompactTyped<KeyAttestationJwt>) -> Boolean = { true },
    /** Turn on to require key attestation support in the [validProofTypes]. */
    private val requireKeyAttestation: Boolean = false,
    /** Used to provide challenges to clients to include in proof of possession of key material. */
    private val clientNonceService: NonceService = DefaultNonceService(),
) {

    /** Valid proof types for [SupportedCredentialFormat.supportedProofTypes]. */
    fun validProofTypes(): Map<String, CredentialRequestProofSupported> = if (requireKeyAttestation) mapOf(
        OpenIdConstants.ProofTypes.JWT to CredentialRequestProofSupported(
            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
            keyAttestationRequired = KeyAttestationRequired()
        ),
        OpenIdConstants.ProofTypes.ATTESTATION to CredentialRequestProofSupported(
            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
            keyAttestationRequired = KeyAttestationRequired()
        )
    ) else mapOf(
        OpenIdConstants.ProofTypes.JWT to CredentialRequestProofSupported(
            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
        )
    )


    /**
     * Provides a fresh nonce to the clients, for incorporating them into the credential proofs.
     *
     * Requests from the client are HTTP POST.
     *
     * MUST be delivered with `Cache-Control: no-store` as HTTP header.
     */
    suspend fun nonce() = ClientNonceResponse(
        clientNonce = clientNonceService.provideNonce()
    )

    @Suppress("DEPRECATION")
    suspend fun validateProofExtractSubjectPublicKeys(
        params: CredentialRequestParameters,
    ): Collection<CryptoPublicKey> = params.proofs?.validateProof()
        ?: throw InvalidProof("proof not contained in request")

    private suspend fun CredentialRequestProofContainer.validateProof() = when {
        jwt != null -> jwtParsed?.flatMap { it.validateJwtProof() }
        attestation != null -> attestationParsed?.flatMap { it.validateAttestationProof() }
        else -> null
    }

    private suspend fun JwsCompactTyped<JsonWebToken>.validateJwtProof(): Collection<CryptoPublicKey> {
        if (jws.jwsHeader.type != OpenIdConstants.PROOF_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature || jws.jwsHeader.algorithm !in supportedAlgorithms) {
            throw InvalidProof("unsupported proof alg: ${jws.jwsHeader.algorithm}")
        }
        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        if (payload.audience == null || payload.audience != publicContext) {
            throw InvalidProof("invalid audience: ${payload.audience}")
        }
        if (payload.issuedAt == null || payload.issuedAt!! > (clock.now() + timeLeeway)) {
            throw InvalidProof("issuedAt in future: ${payload.issuedAt}")
        }
        val keyAttestation = jws.jwsHeader.keyAttestationParsed
        if (requireKeyAttestation && keyAttestation == null) {
            throw InvalidProof("key_attestation not contained in JWT proof")
        }
        if (keyAttestation != null) {
            val attestedKeys = keyAttestation.validateKeyAttestation().ifEmpty {
                throw InvalidProof("key attestation contains no attested keys")
            }
            verifyJwsSignatureWithKey(jws, keyAttestation.payload.attestedKeys.first()).getOrElse {
                throw InvalidProof("JWT proof not signed with key at index 0 of attested_keys", it)
            }
            return attestedKeys
        }

        verifyJwsObject(jws).getOrElse {
            throw InvalidProof("invalid signature: $this.", it)
        }
        return listOf(
            jws.jwsHeader.publicKey ?: throw InvalidProof("could not extract public key from ${jws.jwsHeader}")
        )
    }

    /**
     * OID4VCI 8.2.1.3: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
     * in the `attested_keys` claim.
     */
    private suspend fun JwsCompactTyped<KeyAttestationJwt>.validateAttestationProof(): Collection<CryptoPublicKey> {
                if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        return validateKeyAttestation()
    }

    private suspend fun JwsCompactTyped<KeyAttestationJwt>.validateKeyAttestation(): Collection<CryptoPublicKey> {
        if (jws.jwsHeader.type != OpenIdConstants.KEY_ATTESTATION_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${jws.jwsHeader.type}")
        }
        if (jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
            jws.jwsHeader.algorithm !in supportedAlgorithms
        ) {
            throw InvalidProof("unsupported key attestation alg: ${jws.jwsHeader.algorithm}")
        }
        if (payload.issuer != null) {
            throw InvalidProof("key attestation must not contain iss")
        }
        if (payload.attestedKeys.isEmpty()) {
            throw InvalidProof("key attestation contains no attested_keys")
        }

        if (payload.issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidProof("issuedAt in future: ${payload.issuedAt}")
        }
        if (payload.expiration != null && payload.expiration!! < (clock.now() - timeLeeway)) {
            throw InvalidProof("expiration in past: ${payload.expiration}")
        }
        if (payload.keyStorage.isNullOrEmpty()) {
            throw InvalidProof("key attestation contains no key_storage")
        }
        if (payload.userAuthentication.isNullOrEmpty()) {
            throw InvalidProof("key attestation contains no user_authentication")
        }
        if (payload.certification.isNullOrBlank()) {
            throw InvalidProof("key attestation contains no certification")
        }
        val keyStorageStatus = payload.keyStorageStatus
            ?: throw InvalidProof("key attestation contains no key_storage_status")
        if (keyStorageStatus.expiration < (clock.now() - timeLeeway)) {
            throw InvalidProof("key_storage_status expiration in past: ${keyStorageStatus.expiration}")
        }
        if (!verifyAttestationProof.invoke(this)) {
            throw InvalidProof("key attestation not verified: $this")
        }

        return payload.attestedKeys.map { it.toCryptoPublicKey().getOrThrow() }
    }
}
