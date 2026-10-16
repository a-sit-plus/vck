package at.asitplus.wallet.lib.oidvci

import at.asitplus.catching
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofSupported
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKey
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithKeyFun
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidProof
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.JwtProofChecks
import at.asitplus.wallet.lib.validation.KeyAttestationChecks
import at.asitplus.wallet.lib.validation.KeyAttestationValidationResult
import at.asitplus.wallet.lib.validation.KeyAttestationValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidation
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.TrustValidation
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import at.asitplus.wallet.lib.validation.toOutcome
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

/**
 * Validates the proofs of possession in credential requests of OID4VCI, see [validateProofs].
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class ProofValidator @JvmOverloads constructor(
    /** Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients. */
    internal val publicContext: String = "https://wallet.a-sit.at/credential-issuer",
    /** Used to verify the signature of proof elements in credential requests with the key of the holder. */
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
    /**
     * Validates key attestations: configure it with the anchors of the wallet providers, e.g. from the wallet
     * providers list, and a status list token resolver for `key_storage_status`. Without anchors, key attestations
     * are rejected.
     */
    private val keyAttestationValidator: KeyAttestationValidator = KeyAttestationValidator(),
) {

    /**
     * The checks [validateProofExtractSubjectPublicKeys] has always made: the wallet provider has to be trusted, and
     * the status of key storage components is only checked if it can be resolved.
     */
    private val compatibilityPolicy = ValidationPolicy(
        trust = TrustPolicy.RequireAuthorizedSigner,
        status = if (!keyAttestationValidator.resolvesStatus) StatusPolicy.Skip
        else StatusPolicy.ValidateIfPresent(TrustPolicy.IntegrityOnly),
        timeLeeway = timeLeeway,
        requireTimeliness = true,
    )

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
     * Integrators serve it through [OpenId4VciServer.nonceWithDpopNonce], converted with
     * [OpenId4VciServer.Nonce.toHttpResponse], which sets `Cache-Control: no-store`.
     */
    suspend fun nonce() = ClientNonceResponse(
        clientNonce = clientNonceService.provideNonce()
    )

    /**
     * Validates the proofs in [params] with [validateProofs] under the checks they have always been validated with,
     * and returns the keys to bind credentials to, failing with the first rejection of a proof.
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun validateProofExtractSubjectPublicKeys(
        params: CredentialRequestParameters,
    ): Collection<CryptoPublicKey> {
        val validation = validateProofs(params, compatibilityPolicy)
        validation.proofs.firstOrNull { it.keys == null }?.let { throw it.report.rejection() }
        return validation.keys
    }

    /**
     * Validates every proof of possession in [params] under [policy], see [JwtProofChecks] and [KeyAttestationChecks]:
     * a `jwt` proof (OpenID4VCI 1.0, F.1, F.4), with its key attestation as a child, or an `attestation` proof
     * (F.3). The nonces of all proofs are consumed only if every proof is accepted, so they are not usable again.
     * The clock is read once, all checks use that time.
     *
     * Fails if [params] contains no proof, or a nonce has been used concurrently.
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun validateProofs(
        params: CredentialRequestParameters,
        policy: ValidationPolicy,
    ): ProofsValidation {
        val evaluatedAt = clock.now()
        val container = params.proofs ?: throw InvalidProof("proof not contained in request")
        val proofs = when {
            !container.jwt.isNullOrEmpty() -> container.jwt!!.map { validateJwtProof(it, policy, evaluatedAt) }
            !container.attestation.isNullOrEmpty() ->
                container.attestation!!.map { validateAttestationProof(it, policy, evaluatedAt) }

            else -> throw InvalidProof("proof not contained in request")
        }
        if (proofs.all { it.keys != null }) {
            proofs.flatMap { it.nonces }.toSet().forEach {
                if (!clientNonceService.verifyAndRemoveNonce(it)) throw InvalidNonce("nonce already used: $it")
            }
        }
        return ProofsValidation(proofs)
    }

    /**
     * A `jwt` proof (OpenID4VCI 1.0, F.1), signed with the key at index 0 of `attested_keys` of its key attestation,
     * if any (EUDI TS3, 2.2.2.2), else with the key in its header, which credentials are bound to.
     */
    private suspend fun validateJwtProof(
        proof: JwsCompact,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
    ): ProofValidation {
        val parsed = catching { proof.typed<JsonWebToken, JwsCompact>() }.getOrElse {
            return ProofValidation(
                report = ValidationReport.jwtProof(
                    checks = blockedJwtProof(Failed(InvalidProof("invalid proof", it))),
                    keyAttestation = null,
                    evaluatedAt = evaluatedAt,
                ),
                keys = null,
                nonces = emptySet(),
            )
        }
        val header = parsed.jws.jwsHeader
        val payload = parsed.payload
        val keyAttestation = header.keyAttestation?.let { attestation ->
            catching { attestation.typed<KeyAttestationJwt, JwsCompact>() }.fold(
                onSuccess = { validateKeyAttestation(it, policy, evaluatedAt, embedded = true) },
                onFailure = { null },
            )
        }
        val parsing = catching {
            if (header.type != OpenIdConstants.PROOF_JWT_TYPE) throw InvalidProof("invalid typ: ${header.type}")
            if (header.algorithm !is JwsAlgorithm.Signature || header.algorithm !in supportedAlgorithms) {
                throw InvalidProof("unsupported proof alg: ${header.algorithm}")
            }
            if (payload.audience == null) throw InvalidProof("proof contains no aud")
            if (payload.issuedAt == null) throw InvalidProof("proof contains no iat")
            if (listOfNotNull(header.keyId, header.jsonWebKey, header.certificateChain).size > 1) {
                throw InvalidProof("proof contains more than one of kid, jwk and x5c")
            }
            if (header.keyAttestation != null && keyAttestation == null) {
                throw InvalidProof("key_attestation in JWT proof can not be parsed")
            }
            if (requireKeyAttestation && header.keyAttestation == null) {
                throw InvalidProof("key_attestation not contained in JWT proof")
            }
        }.toOutcome()
        val attestedKey = keyAttestation?.attestation?.payload?.attestedKeys?.firstOrNull()
        val signature = when {
            keyAttestation != null && attestedKey != null -> verifyJwsSignatureWithKey(parsed.jws, attestedKey)
                .fold(
                    onSuccess = { Passed },
                    onFailure = {
                        Failed(InvalidProof("JWT proof not signed with key at index 0 of attested_keys", it))
                    },
                )

            keyAttestation != null -> Blocked()
            else -> verifyJwsObject(parsed.jws)
                .fold(onSuccess = { Passed }, onFailure = { Failed(InvalidProof("invalid signature", it)) })
        }
        val checks = JwtProofChecks(
            parsing = parsing,
            signature = signature,
            proofTime = payload.issuedAt?.let {
                if (it > evaluatedAt + policy.timeLeeway) {
                    Failed(TimelinessException("issuedAt in future: $it", evaluatedAt, notBefore = it, notAfter = null))
                } else Passed
            } ?: Blocked(),
            nonce = nonceOutcome(payload.nonce),
            audience = if (payload.audience == publicContext) Passed
            else Failed(InvalidProof("invalid audience: ${payload.audience}")),
        )
        val report = ValidationReport.jwtProof(checks, keyAttestation?.result?.report, evaluatedAt)
        val accepted = report.decision == ValidationDecision.ACCEPTED
        return ProofValidation(
            report = report,
            keys = if (!accepted) null
            else keyAttestation?.result?.attestedKeys
                ?: listOf(header.publicKey ?: throw InvalidProof("could not extract public key from $header")),
            nonces = setOfNotNull(payload.nonce, keyAttestation?.attestation?.payload?.nonce),
        )
    }

    /**
     * An `attestation` proof (OpenID4VCI 1.0, F.3): the Credential Issuer SHOULD issue a Credential for each key in
     * `attested_keys` (8.2.1.3).
     */
    private suspend fun validateAttestationProof(
        proof: JwsCompact,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
    ): ProofValidation {
        val parsed = catching { proof.typed<KeyAttestationJwt, JwsCompact>() }.getOrElse {
            return ProofValidation(
                report = ValidationReport.keyAttestation(
                    checks = blockedKeyAttestation(Failed(InvalidProof("invalid proof", it))),
                    policy = policy,
                    evaluatedAt = evaluatedAt,
                ),
                keys = null,
                nonces = emptySet(),
            )
        }
        val result = validateKeyAttestation(parsed, policy, evaluatedAt, embedded = false).result
        return ProofValidation(result.report, result.attestedKeys, setOfNotNull(parsed.payload.nonce))
    }

    private class EmbeddedKeyAttestation(
        val attestation: JwsCompactTyped<KeyAttestationJwt>,
        val result: KeyAttestationValidationResult,
    )

    /**
     * With a Nonce Endpoint, a key attestation contains a server-provided `c_nonce`, as `attestation` proof
     * (OpenID4VCI 1.0, F.3) and embedded in a `jwt` proof (F.1), where it need not be the nonce of the proof.
     */
    private suspend fun validateKeyAttestation(
        attestation: JwsCompactTyped<KeyAttestationJwt>,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
        embedded: Boolean,
    ) = EmbeddedKeyAttestation(
        attestation = attestation,
        result = keyAttestationValidator.validate(
            attestation = attestation,
            policy = policy,
            evaluatedAt = evaluatedAt,
            embedded = embedded,
            nonce = nonceOutcome(attestation.payload.nonce),
            supportedAlgorithms = supportedAlgorithms,
        ),
    )

    /** "the nonce in the key proof matches the server-provided c_nonce value" (OpenID4VCI 1.0, F.4) */
    private suspend fun nonceOutcome(nonce: String?): CheckOutcome =
        if (nonce != null && clientNonceService.verifyNonce(nonce)) Passed
        else Failed(InvalidNonce("invalid nonce: $nonce"))

    private fun blockedJwtProof(parsing: CheckOutcome) =
        JwtProofChecks(parsing, Blocked(), Blocked(), Blocked(), Blocked())

    private fun blockedKeyAttestation(parsing: CheckOutcome) = KeyAttestationChecks(
        parsing = parsing,
        signature = Blocked(),
        trust = TrustValidation(Blocked()),
        timeliness = Blocked(),
        status = StatusValidation(claim = Blocked(), agreement = Blocked()),
        nonce = Blocked(),
    )
}

/** The validation of every proof of a credential request, see [ProofValidator.validateProofs]. */
data class ProofsValidation(
    val proofs: List<ProofValidation>,
) {
    /** Whether every proof is accepted, so credentials may be issued for [keys]. */
    val accepted: Boolean
        get() = proofs.all { it.keys != null }

    /** The keys of all accepted proofs to bind credentials to. */
    val keys: List<CryptoPublicKey>
        get() = proofs.flatMap { it.keys.orEmpty() }
}

/**
 * The [report] of one proof, see [JwtProofChecks] and [KeyAttestationChecks], and the [keys] to bind credentials to,
 * if it has been accepted.
 */
data class ProofValidation(
    val report: ValidationReport,
    val keys: Collection<CryptoPublicKey>?,
    internal val nonces: Set<String>,
)

/**
 * Why a proof is rejected, as [OAuth2Exception]: the cause of the first check that does not pass, an invalid nonce as
 * [InvalidNonce] (OpenID4VCI 1.0, 8.3.1.2), anything else as [InvalidProof].
 */
private fun ValidationReport.rejection(): OAuth2Exception {
    val outcomes = when (val checks = checks) {
        is JwtProofChecks -> listOf(checks.parsing, checks.nonce, checks.audience, checks.proofTime) +
                children.map { it.keyAttestationRejection() } + checks.signature

        is KeyAttestationChecks -> listOf(keyAttestationRejection())
        else -> emptyList()
    }
    val cause = outcomes.filterIsInstance<Failed>().firstOrNull()?.throwable
        ?: outcomes.filterIsInstance<Blocked>().firstOrNull()?.cause
        ?: return InvalidProof("proof not accepted")
    return cause as? OAuth2Exception ?: InvalidProof(cause.message, cause)
}

/** The first rejection of a key attestation, with the messages the legacy validator used. */
private fun ValidationReport.keyAttestationRejection(): CheckOutcome {
    if (decision == ValidationDecision.ACCEPTED) return Passed
    val checks = checks as KeyAttestationChecks
    fun Throwable?.wrap(message: String) = Failed(InvalidProof(message, this))
    return when {
        checks.nonce is Failed -> checks.nonce
        checks.parsing is Failed -> (checks.parsing as Failed).throwable.let { Failed(InvalidProof(it.message, it)) }
        checks.timeliness is Failed ->
            (checks.timeliness as Failed).throwable.let { Failed(InvalidProof(it.message, it)) }
        checks.signature != Passed -> checks.signature.cause().wrap("key attestation not verified")
        checks.trust.outcome != Passed -> checks.trust.outcome.cause().wrap("key attestation not verified")
        else -> checks.status.mechanisms.firstNotNullOfOrNull { it.outcome as? Failed }?.throwable
            .wrap("TokenStatus invalid")
    }
}

private fun CheckOutcome.cause(): Throwable? = when (this) {
    is Failed -> throwable
    is Blocked -> cause
    else -> null
}
