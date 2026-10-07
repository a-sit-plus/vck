package at.asitplus.wallet.lib.oidvci

import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.KmmResult
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
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.toTokenStatusResolver
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKey
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKeyFun
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidProof
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import kotlin.jvm.JvmOverloads
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
class ProofValidator @JvmOverloads constructor(
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
    /** Turn on to require key attestation support in the [validProofTypes]. */
    private val requireKeyAttestation: Boolean = false,
    /** Used to provide challenges to clients to include in proof of possession of key material. */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /** Used to verify the validity of a key attestation. */
    private val statusListTokenResolver: StatusListTokenResolver? = null,
    /**
     * Used to verify the signature of the key attestation statements, i.e. to establish trust in the wallet provider.
     * Without a configured verifier, key attestations are rejected. To accept key attestations of trusted
     * wallet providers, e.g. as listed in a List of Trusted Entities, pass
     * [at.asitplus.wallet.lib.jws.VerifyJwsObjectTrustedCertificate] with their certificates.
     */
    private val verifyKeyAttestationSignature: VerifyJwsObjectFun = VerifyJwsObjectFun {
        KmmResult.failure(IllegalStateException("No trusted key attestation verifier configured"))
    },
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
    ): Collection<CryptoPublicKey> = params.proofs?.validateProof()?.let {
        it.nonces.forEach {
            if (!clientNonceService.verifyAndRemoveNonce(it))
                throw InvalidNonce("nonce already used: $it")
        }
        it.keys
    } ?: throw InvalidProof("proof not contained in request")

    /** Small container to expire nonces only after collecting all proofs and extracting all keys */
    private data class KeysAndNonces(
        val keys: Collection<CryptoPublicKey>,
        val nonces: Set<String>,
    )

    private suspend fun CredentialRequestProofContainer.validateProof(): KeysAndNonces? = when {
        jwt != null -> jwtParsed?.map { it.validateJwtProof() }
            ?.takeIf { it.isNotEmpty() }
            ?.reduce { acc, nonces -> KeysAndNonces(acc.keys + nonces.keys, acc.nonces + nonces.nonces) }

        attestation != null -> attestationParsed?.map { it.validateAttestationProof() }
            ?.takeIf { it.isNotEmpty() }
            ?.reduce { acc, nonces -> KeysAndNonces(acc.keys + nonces.keys, acc.nonces + nonces.nonces) }

        else -> null
    }

    private suspend fun JwsCompactTyped<JsonWebToken, JwsHeader>.validateJwtProof(): KeysAndNonces {
        if (wrappedHeader.header.type != OpenIdConstants.PROOF_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${wrappedHeader.header.type}")
        }
        if (wrappedHeader.header.algorithm !is JwsAlgorithm.Signature || wrappedHeader.header.algorithm !in supportedAlgorithms) {
            throw InvalidProof("unsupported proof alg: ${wrappedHeader.header.algorithm}")
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
        val keyAttestation = wrappedHeader.header.keyAttestationParsed
        if (requireKeyAttestation && keyAttestation == null) {
            throw InvalidProof("key_attestation not contained in JWT proof")
        }
        if (keyAttestation != null) {
            val attestedKeys = keyAttestation.validateKeyAttestation()
            verifyJwsSignatureWithKey(jws, keyAttestation.payload.attestedKeys.first()).getOrElse {
                throw InvalidProof("JWT proof not signed with key at index 0 of attested_keys", it)
            }
            return KeysAndNonces(
                keys = attestedKeys,
                nonces = setOf(payload.nonce!!)
            )
        }

        verifyJwsObject(jws).getOrElse {
            throw InvalidProof("invalid signature: $this.", it)
        }
        return KeysAndNonces(
            keys = listOf(
                wrappedHeader.header.publicKey ?: throw InvalidProof("could not extract public key from ${wrappedHeader.header}")
            ),
            nonces = setOf(payload.nonce!!)
        )
    }

    /**
     * OID4VCI 8.2.1.3: The Credential Issuer SHOULD issue a Credential for each cryptographic public key specified
     * in the `attested_keys` claim.
     */
    private suspend fun JwsCompactTyped<KeyAttestationJwt, JwsHeader>.validateAttestationProof(): KeysAndNonces {
        if (payload.nonce == null || !clientNonceService.verifyNonce(payload.nonce!!)) {
            throw InvalidNonce("invalid nonce: ${payload.nonce}")
        }
        return KeysAndNonces(
            keys = validateKeyAttestation(),
            nonces = setOf(payload.nonce!!)
        )
    }

    private suspend fun JwsCompactTyped<KeyAttestationJwt, JwsHeader>.validateKeyAttestation(): Collection<CryptoPublicKey> {
        if (wrappedHeader.header.type != OpenIdConstants.KEY_ATTESTATION_JWT_TYPE) {
            throw InvalidProof("invalid typ: ${wrappedHeader.header.type}")
        }
        if (wrappedHeader.header.algorithm !is JwsAlgorithm.Signature ||
            wrappedHeader.header.algorithm !in supportedAlgorithms
        ) {
            throw InvalidProof("unsupported key attestation alg: ${wrappedHeader.header.algorithm}")
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

        val statusList = keyStorageStatus.status[StatusListInfo.SerialNames.STATUS_LIST_INFO]
            ?: throw InvalidProof("Unknown status information in status")
        val statusListInfo = Json.decodeFromJsonElement<StatusListInfo>(statusList)
        val tokenStatus = statusListTokenResolver?.toTokenStatusResolver()?.invoke(statusListInfo)
            ?.getOrElse { throw InvalidProof("could not resolve key_storage_status", it) }
        if (tokenStatus?.isValid == false) {
            throw InvalidProof("TokenStatus invalid")
        }

        verifyKeyAttestationSignature(jws)
            .onFailure { throw InvalidProof("key attestation not verified: $this", it) }

        return payload.attestedKeys.map { it.toCryptoPublicKey().getOrThrow() }
    }
}
