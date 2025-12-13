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
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
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
    /** Supported signing algorithms, which may be used from clients in proofs to request credentials. */
    private val supportedAlgorithms: Collection<JwsAlgorithm.Signature> = listOf(JwsAlgorithm.Signature.ES256),
    /** Clock used to verify timestamps in proof elements in credential requests. */
    private val clock: Clock = Clock.System,
    /** Time leeway for verification of timestamps in proof elements in credential requests. */
    private val timeLeeway: Duration = 5.minutes,
    /** Callback to verify a received [KeyAttestationJwt] proof in credential requests. */
    private val verifyAttestationProof: (JwsSigned<KeyAttestationJwt>) -> Boolean = { true },
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

    private suspend fun JwsSigned<JsonWebToken>.validateJwtProof(): Collection<CryptoPublicKey> {
        if (header.type != OpenIdConstants.PROOF_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${header.type}")
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
        verifyJwsObject(this).getOrElse {
            throw InvalidProof("invalid signature: $this.", it)
        }
        // OID4VCI F.1.: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
        // in the attested_keys claim within the key_attestation parameter.
        val additionalKeys = header.keyAttestationParsed?.validateAttestationProof() ?: listOf()

        val headerPublicKey = header.publicKey
            ?: throw InvalidProof("could not extract public key from $header")

        return additionalKeys + headerPublicKey
    }

    /**
     * OID4VCI 8.2.1.3: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
     * in the `attested_keys` claim.
     */
    private suspend fun JwsSigned<KeyAttestationJwt>.validateAttestationProof(): Collection<CryptoPublicKey> {
        if (header.type != OpenIdConstants.KEY_ATTESTATION_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${header.type}")
        }
        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        if (payload.issuedAt > (clock.now() + timeLeeway)) {
            throw InvalidProof("issuedAt in future: ${payload.issuedAt}")
        }
        if (payload.expiration != null && payload.expiration!! < (clock.now() - timeLeeway)) {
            throw InvalidProof("expiration in past: ${payload.expiration}")
        }
        if (!verifyAttestationProof.invoke(this)) {
            throw InvalidProof("key attestation not verified: $this")
        }
        return payload.attestedKeys.map { it.toCryptoPublicKey().getOrThrow() }
    }
}