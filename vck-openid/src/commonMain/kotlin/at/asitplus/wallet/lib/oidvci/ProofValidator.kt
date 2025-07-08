package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProof
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ProofType.*
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
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
    /** Callback to verify a received [at.asitplus.signum.indispensable.josef.KeyAttestationJwt] proof in credential requests. */
    private val verifyAttestationProof: (JwsSigned<KeyAttestationJwt>) -> Boolean = { true },
    /** Turn on to require key attestation support in the [validProofTypes]. */
    private val requireKeyAttestation: Boolean = false,
    /** Used to provide challenges to clients to include in proof of possession of key material. */
    private val clientNonceService: NonceService = DefaultNonceService(),
) {

    /** Valid proof types for [SupportedCredentialFormat.supportedProofTypes]. */
    fun validProofTypes(): Map<String, CredentialRequestProofSupported> = if (requireKeyAttestation) mapOf(
        JWT.stringRepresentation to CredentialRequestProofSupported(
            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
            keyAttestationRequired = KeyAttestationRequired()
        ),
        ATTESTATION.stringRepresentation to CredentialRequestProofSupported(
            supportedSigningAlgorithms = supportedAlgorithms.map { it.identifier },
            keyAttestationRequired = KeyAttestationRequired()
        )
    ) else mapOf(
        JWT.stringRepresentation to CredentialRequestProofSupported(
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
    suspend fun nonce() = catching {
        ClientNonceResponse(
            clientNonce = clientNonceService.provideNonce()
        )
    }

    suspend fun validateProofExtractSubjectPublicKeys(
        params: CredentialRequestParameters,
    ): Collection<CryptoPublicKey> = params.proof?.validateProof()
        ?: params.proofs?.validateProof()
        ?: throw OAuth2Exception.InvalidRequest("invalid proof")
            .also { Napier.w("credential: client did not provide proof of possession in $params") }

    private suspend fun CredentialRequestProof.validateProof() = when (proofType) {
        JWT -> jwtParsed?.validateJwtProof()
        ATTESTATION -> attestationParsed?.validateAttestationProof()
        else -> null
    }

    private suspend fun CredentialRequestProofContainer.validateProof() = when (proofType) {
        JWT -> jwtParsed?.flatMap { it.validateJwtProof() }
        ATTESTATION -> attestationParsed?.flatMap { it.validateAttestationProof() }
        else -> jwtParsed?.flatMap { it.validateJwtProof() }
            ?: attestationParsed?.flatMap { it.validateAttestationProof() }
    }

    private suspend fun JwsSigned<JsonWebToken>.validateJwtProof(): Collection<CryptoPublicKey> {
        if (header.type != OpenIdConstants.PROOF_JWT_TYPE) {
            Napier.w("validateJwtProof: invalid typ: $header")
            throw OAuth2Exception.InvalidProof("invalid typ: ${header.type}")
        }

        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            Napier.w("validateJwtProof: invalid nonce: ${payload.nonce}")
            throw OAuth2Exception.InvalidNonce("invalid nonce: ${payload.nonce}")
        }

        if (payload.audience == null || payload.audience != publicContext) {
            Napier.w("validateJwtProof: invalid audience: ${payload.audience}")
            throw OAuth2Exception.InvalidProof("invalid audience: ${payload.audience}")
        }

        if (!verifyJwsObject(this)) {
            Napier.w("validateJwtProof: invalid signature: $this")
            throw OAuth2Exception.InvalidProof("invalid signature: $this")
        }
        // OID4VCI 8.2.1.1: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
        // in the attested_keys claim within the key_attestation parameter.
        val additionalKeys = header.keyAttestationParsed?.validateAttestationProof() ?: listOf()

        val headerPublicKey = header.publicKey ?: run {
            Napier.w("validateJwtProof: No valid key in header: $header")
            throw OAuth2Exception.InvalidProof("could not extract public key")
        }

        return additionalKeys + headerPublicKey
    }

    /**
     * OID4VCI 8.2.1.3: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
     * in the `attested_keys` claim.
     */
    private suspend fun JwsSigned<KeyAttestationJwt>.validateAttestationProof(): Collection<CryptoPublicKey> {
        if (header.type != OpenIdConstants.KEY_ATTESTATION_JWT_TYPE) {
            Napier.w("validateAttestationProof: invalid typ: $header")
            throw OAuth2Exception.InvalidProof("invalid typ: ${header.type}")
        }
        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            Napier.w("validateAttestationProof: invalid nonce: ${payload.nonce}")
            throw OAuth2Exception.InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        if (payload.issuedAt > (clock.now() + timeLeeway)) {
            Napier.w("validateAttestationProof: issuedAt in future: ${payload.issuedAt}")
            throw OAuth2Exception.InvalidProof("issuedAt in future: ${payload.issuedAt}")
        }

        if (payload.expiration != null && payload.expiration!! < (clock.now() - timeLeeway)) {
            Napier.w("validateAttestationProof: expiration in past: ${payload.expiration}")
            throw OAuth2Exception.InvalidProof("expiration in past: ${payload.expiration}")
        }

        if (!verifyAttestationProof.invoke(this)) {
            Napier.w("validateAttestationProof: Key attestation not verified by callback: $this")
            throw OAuth2Exception.InvalidProof("key attestation not verified: $this")
        }
        return payload.attestedKeys.mapNotNull {
            it.toCryptoPublicKey()
                .onFailure { Napier.w("validateAttestationProof: Could not convert to public key", it) }
                .getOrNull()
        }
    }
}