package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod.AttestationPopJwt
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod.DpopCombined
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService.Companion.DEFAULT_WALLET_ATTESTATION_ALGORITHMS
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidClient
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.UseAttestationChallenge
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.UseFreshAttestation
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ClientAttestationChecks
import at.asitplus.wallet.lib.validation.ClientAttestationPossession
import at.asitplus.wallet.lib.validation.ClientAttestationValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
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
 * Client authentication service for an OAuth2.0 AS, based on Attestation-Based Client Authentication, see
 * [validate].
 *
 * Implemented from:
 * * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 * * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
class AttestationBasedClientAuthenticationService @JvmOverloads constructor(
    private val acceptedPopMethods: Set<ClientAttestationPopMethod> =
        setOf(AttestationPopJwt),
    /**
     * Validates client attestations: configure it with the anchors of the wallet providers, e.g. from the wallet
     * providers list, and a status list token resolver for `client_status`. Without anchors, client attestations
     * are rejected.
     */
    private val clientAttestationValidator: ClientAttestationValidator = ClientAttestationValidator(),
    /** Used to verify client attestation PoP JWTs with the `cnf` of the client attestation. */
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    /** Clock used to verify WIA and WIA PoP timestamps. */
    private val clock: Clock = Clock.System,
    /** Time leeway for verification of WIA and WIA PoP timestamps. */
    private val timeLeeway: Duration = 5.minutes,
    /** Maximum age of WIA PoP JWTs. */
    private val maxAgePoP: Duration = 10.minutes,
    /** Identifier of this authorization server, to verify `aud` of incoming PoP JWTs. */
    private val issuerIdentifier: String? = null,
    /** Used for [OAuth2AuthorizationServerMetadata.clientAttestationSigningAlgValuesSupportedStrings] */
    private val supportedSigningAlgorithms: Set<JwsAlgorithm.Signature> = DEFAULT_WALLET_ATTESTATION_ALGORITHMS,
    /**
     * Service used to create challenges for the clients to use in PoP JWT.
     *
     * For [OpenIdConstants.ClientAttestationPopMethod.DpopCombined] the challenge is carried in the DPoP proof's
     * `nonce`, so pass the same instance as `dpopNonceService` of [TokenService.jwt].
     */
    private val nonceService: NonceService = DefaultNonceService(),
) : ClientAuthenticationService {

    init {
        require(acceptedPopMethods.all { it == DpopCombined || it == AttestationPopJwt }
                && acceptedPopMethods.isNotEmpty()) {
            "acceptedPopMethods must contain only $DpopCombined or $AttestationPopJwt"
        }
    }

    /**
     * The checks [authenticateClient] has always made: the wallet provider has to be trusted, and the status of
     * wallet instances is only checked if it can be resolved.
     */
    private val compatibilityPolicy = ValidationPolicy(
        trust = TrustPolicy.RequireAuthorizedSigner,
        status = if (!clientAttestationValidator.resolvesStatus) StatusPolicy.Skip
        else StatusPolicy.ValidateIfPresent(TrustPolicy.IntegrityOnly),
        timeLeeway = timeLeeway,
        requireTimeliness = true,
    )

    override val supportedAuthMethods: Set<String>
        get() = acceptedPopMethods.mapNotNull { it.clientAuthMethod }.toSet()

    override val supportedPopSigningAlgs: Set<String>
        get() = supportedSigningAlgorithms.map { it.identifier }.toSet()

    override val supportedSigningAlgs: Set<String>
        get() = supportedSigningAlgorithms.map { it.identifier }.toSet()

    override val supportedPopMethods: Set<ClientAttestationPopMethod>
        get() = acceptedPopMethods

    override suspend fun getAttestationChallenge(): String = nonceService.provideNonce()

    /**
     * Authenticates the client as defined from a client attestation JWT, with [validate] under the checks it has
     * always been authenticated with, failing with the first rejection.
     */
    override suspend fun authenticateClient(
        httpRequest: RequestInfo?,
        clientId: String?,
        validatedClientKey: JsonWebKey?,
    ): KmmResult<AuthenticatedClient> = catching {
        val validation = validate(httpRequest, clientId, validatedClientKey, compatibilityPolicy)
        validation.client ?: throw validation.report.rejection()
    }

    /**
     * Validates the client attestation and its proof of possession in [httpRequest] under [policy], see
     * [ClientAttestationValidator.validate] and [ClientAttestationChecks]: with a client attestation PoP JWT
     * (draft-ietf-oauth-attestation-based-client-auth-10, 5.2), or, if [DpopCombined] is accepted, with the DPoP proof
     * whose key is [validatedClientKey] (6). The challenge is consumed only if the client attestation is accepted, so
     * it is not usable again. The clock is read once, all checks use that time.
     *
     * Fails if [httpRequest] contains no client attestation, or the challenge has been used concurrently.
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun validate(
        httpRequest: RequestInfo?,
        clientId: String?,
        validatedClientKey: JsonWebKey?,
        policy: ValidationPolicy,
    ): ClientAttestationValidation {
        val evaluatedAt = clock.now()
        val attestation = httpRequest?.clientAttestation
            ?: throw InvalidClient("client attestation header missing")
        val pop = httpRequest.clientAttestationPop
        val possession = possession(pop, attestation.payload, validatedClientKey, policy, evaluatedAt)
        val result = clientAttestationValidator.validate(
            attestation = attestation,
            clientId = clientId,
            possession = possession,
            policy = policy,
            evaluatedAt = evaluatedAt,
            supportedAlgorithms = supportedSigningAlgorithms,
        )
        val confirmationKey = result.confirmationKey
            ?: return ClientAttestationValidation(result.report, client = null)
        pop?.payload?.attestationChallenge?.let {
            if (!nonceService.verifyAndRemoveNonce(it)) {
                throw useAttestationChallenge("client attestation PoP challenge invalid")
            }
        }
        val client = AuthenticatedClient(clientId = attestation.payload.subject!!, publicKey = confirmationKey)
        return ClientAttestationValidation(result.report, client)
    }

    /**
     * The checks of the proof of possession: a client attestation PoP JWT, or the DPoP proof in [DpopCombined].
     */
    private suspend fun possession(
        pop: JwsCompactTyped<JsonWebToken>?,
        attestation: JsonWebToken,
        validatedClientKey: JsonWebKey?,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
    ): ClientAttestationPossession = when {
        pop != null && acceptedPopMethods.singleOrNull() == DpopCombined ->
            missingPossession(InvalidClient("client attestation PoP header not allowed in combined-only mode"))

        pop != null -> popJwtPossession(pop, attestation, policy, evaluatedAt)
        DpopCombined in acceptedPopMethods -> ClientAttestationPossession(
            parsing = Passed,
            signature = dpopKeyMatches(validatedClientKey, attestation),
            time = NotApplicable,
            audience = NotApplicable,
            challenge = NotApplicable,
        )

        else -> missingPossession(InvalidClient("client attestation pop header missing"))
    }

    /** "The public key from the DPoP proof's jwk header [...] MUST match the cnf key" (6) */
    private fun dpopKeyMatches(validatedClientKey: JsonWebKey?, attestation: JsonWebToken): CheckOutcome {
        val dpopPublicKey = validatedClientKey?.toCryptoPublicKey()?.getOrNull()
            ?: return Failed(InvalidClient("DPoP header missing"))
        val cnfPublicKey = attestation.confirmationClaim?.jsonWebKey?.toCryptoPublicKey()?.getOrNull()
            ?: return Blocked()
        return if (dpopPublicKey == cnfPublicKey) Passed
        else Failed(InvalidClient("DPoP key does not match client attestation key"))
    }

    /**
     * A client attestation PoP JWT (draft-ietf-oauth-attestation-based-client-auth-10, 5.2): `typ`, `alg`, `aud`,
     * `jti`, and `iat` present, signed with the `cnf` key of the attestation, created recently, for this server, with
     * a challenge of this server. `iss` and `exp` are no longer defined, but checked if present, and the challenge is
     * also accepted as `nonce`, as in earlier drafts.
     */
    private suspend fun popJwtPossession(
        pop: JwsCompactTyped<JsonWebToken>,
        attestation: JsonWebToken,
        policy: ValidationPolicy,
        evaluatedAt: Instant,
    ): ClientAttestationPossession {
        val payload = pop.payload
        val cnf = attestation.confirmationClaim
        return ClientAttestationPossession(
            parsing = catching {
                if (pop.jws.jwsHeader.type != JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT) {
                    throw InvalidClient("invalid client attestation PoP typ: ${pop.jws.jwsHeader.type}")
                }
                if (pop.jws.jwsHeader.algorithm !is JwsAlgorithm.Signature ||
                    pop.jws.jwsHeader.algorithm !in supportedSigningAlgorithms
                ) {
                    throw InvalidClient("unsupported client attestation PoP alg: ${pop.jws.jwsHeader.algorithm}")
                }
                if (payload.audience == null) throw InvalidClient("client attestation PoP has no aud")
                if (payload.jwtId == null) throw InvalidClient("client attestation PoP has no jti")
                if (payload.issuedAt == null) throw InvalidClient("client attestation PoP has no iat")
            }.toOutcome(),
            signature = when {
                cnf == null -> Blocked()
                !verifyJwsSignatureWithCnf(pop.jws, cnf) ->
                    Failed(InvalidClient("client attestation PoP JWT not verified"))

                payload.issuer != null && attestation.subject != null && payload.issuer != attestation.subject ->
                    Failed(InvalidClient("client attestation PoP issuer not equal to attestation subject"))

                else -> Passed
            },
            time = popTime(payload, policy, evaluatedAt),
            audience = when {
                issuerIdentifier == null -> NotApplicable
                payload.audience == issuerIdentifier -> Passed
                else -> Failed(
                    InvalidClient(
                        "client attestation PoP aud '${payload.audience}' does not match issuer '$issuerIdentifier'"
                    )
                )
            },
            challenge = when (val challenge = payload.attestationChallenge) {
                null -> Failed(useAttestationChallenge("client attestation PoP missing challenge/nonce"))
                else -> if (nonceService.verifyNonce(challenge)) Passed
                else Failed(useAttestationChallenge("client attestation PoP challenge invalid"))
            },
        )
    }

    /** "the creation time of the JWT [...] is within an acceptable window" (5.2), never relaxed by [policy]. */
    private fun popTime(payload: JsonWebToken, policy: ValidationPolicy, evaluatedAt: Instant): CheckOutcome {
        val issuedAt = payload.issuedAt ?: return Blocked()
        val expiration = payload.expiration
        return when {
            issuedAt > evaluatedAt + policy.timeLeeway ->
                Failed(InvalidClient("client attestation PoP iat in future: $issuedAt"))

            issuedAt < evaluatedAt - maxAgePoP - policy.timeLeeway ->
                Failed(InvalidClient("client attestation PoP issued too long ago: $issuedAt"))

            expiration != null && expiration < evaluatedAt - policy.timeLeeway ->
                Failed(InvalidClient("client attestation PoP expired: $expiration"))

            else -> Passed
        }
    }

    /** "use_attestation_challenge", with a fresh challenge (7) */
    private suspend fun useAttestationChallenge(description: String) =
        UseAttestationChallenge(nonceService.provideNonce(), description)

    private fun missingPossession(cause: OAuth2Exception) =
        ClientAttestationPossession(Passed, Failed(cause), Blocked(), Blocked(), Blocked())

    /** The challenge in `challenge`, or in `nonce` as in earlier drafts. */
    private val JsonWebToken.attestationChallenge: String?
        get() = challenge ?: nonce
}

/**
 * The [report] of a client attestation and its proof of possession, see [ClientAttestationChecks], and the
 * authenticated [client], if it has been accepted.
 */
data class ClientAttestationValidation(
    val report: ValidationReport,
    val client: AuthenticatedClient?,
)

/**
 * Why a client attestation is rejected, as [OAuth2Exception]: the cause of the first check that does not pass, an
 * attestation that is not timely as [UseFreshAttestation], an invalid challenge as [UseAttestationChallenge]
 * (draft-ietf-oauth-attestation-based-client-auth-10, 7), anything else as [InvalidClient].
 */
private fun ValidationReport.rejection(): OAuth2Exception {
    val checks = checks as? ClientAttestationChecks ?: return InvalidClient("client attestation not accepted")
    fun CheckOutcome.wrap(wrap: (String?, Throwable?) -> OAuth2Exception) = when (this) {
        is Failed -> Failed(throwable as? OAuth2Exception ?: wrap(throwable.message, throwable))
        else -> this
    }
    fun CheckOutcome.notVerified() = when (this) {
        is Failed -> Failed(InvalidClient("client attestation JWT not verified", throwable))
        is Blocked -> Blocked(InvalidClient("client attestation JWT not verified", cause))
        else -> this
    }
    val outcomes = listOf(
        checks.parsing.wrap(::InvalidClient),
        checks.clientId.wrap(::InvalidClient),
        checks.timeliness.wrap(::UseFreshAttestation),
        checks.signature.notVerified(),
        checks.trust.outcome.notVerified(),
        checks.popSignature,
        checks.popTime,
        checks.audience,
        checks.challenge,
        checks.status.claim,
    ) + checks.status.mechanisms.map { mechanism ->
        mechanism.outcome.wrap { _, cause -> InvalidClient("client_status invalid", cause) }
    }
    val cause = outcomes.filterIsInstance<Failed>().firstOrNull()?.throwable
        ?: outcomes.filterIsInstance<Blocked>().firstOrNull()?.cause
        ?: return InvalidClient("client attestation not accepted")
    return cause as? OAuth2Exception ?: InvalidClient(cause.message, cause)
}
