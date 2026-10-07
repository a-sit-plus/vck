package at.asitplus.wallet.lib.validation

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.extractTokenStatus
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * The anchors that authorize the signers of the status list tokens an artifact references, independently of the
 * signer of the artifact itself.
 */
sealed interface StatusSignerAnchors {
    /**
     * The status anchors of the credential type [credentialIdentifier], see [CredentialTrustAnchors]. Without an
     * identifier, i.e. for a credential whose type is ambiguous, the signers can not be authorized.
     */
    data class OfCredentialType(
        val anchors: CredentialTrustAnchors?,
        val credentialIdentifier: String?,
    ) : StatusSignerAnchors

    /**
     * Anchors of an artifact kind, e.g. the revocation services of the wallet providers list for key attestations
     * and wallet attestations, reported as [source].
     */
    data class OfArtifactKind(
        val anchors: TrustedCertificates?,
        val source: String,
    ) : StatusSignerAnchors
}

/**
 * Validates the status of an artifact, i.e. every status mechanism it advertises, following the validation rules of
 * Token Status List (draft-ietf-oauth-status-list-21, 8.3): each status list token gets a report of its own
 * (retrieval, media type, signature, signer, subject, and time), and the status is only taken from a token that is
 * accepted.
 *
 * The signers of status list tokens have to be issued by an anchor of [StatusSignerAnchors], never directly trusted,
 * as the trust anchor must not be included in `x5c` and the signer must not be self-signed (OpenID4VC HAIP 1.0, 6.1).
 */
class StatusValidator @JvmOverloads constructor(
    /** Retrieves status list tokens. Without one, a status claim can not be checked, which blocks it. */
    private val statusListTokenResolver: StatusListTokenResolver? = null,
    private val signatureCheck: SignatureCheck = SignatureCheck(),
    private val zlibService: ZlibService = DefaultZlibService(),
) {

    /**
     * Validates [status], the status claim of an artifact (`null` if it has none), under [policy], at [evaluatedAt]
     * with [timeLeeway]. Every mechanism is resolved, concurrently, and reported.
     */
    suspend fun validate(
        status: TokenStatusInfo?,
        signerAnchors: StatusSignerAnchors,
        policy: StatusPolicy,
        timeLeeway: Duration,
        evaluatedAt: Instant,
    ): StatusValidation {
        val claim = statusClaimOutcome(policy, claimPresent = status != null)
        val signerTrust = policy.signerTrust
        if (status == null || claim != Passed || signerTrust == null) {
            return StatusValidation(claim, mechanisms = emptyList(), agreement = NotApplicable)
        }
        val mechanisms = coroutineScope {
            status.mechanisms.map { reference ->
                async { validate(reference, signerAnchors, signerTrust, policy, timeLeeway, evaluatedAt) }
            }.awaitAll()
        }
        return StatusValidation(claim, mechanisms, statusAgreement(mechanisms))
    }

    private suspend fun validate(
        reference: RevocationListInfo,
        signerAnchors: StatusSignerAnchors,
        signerTrust: TrustPolicy,
        policy: StatusPolicy,
        timeLeeway: Duration,
        evaluatedAt: Instant,
    ): StatusMechanismValidation {
        val retrieved: KmmResult<StatusListToken> = catching {
            requireNotNull(statusListTokenResolver) { "No status list token resolver configured" }
            statusListTokenResolver(reference.uri)
        }
        val (checks, payload) = retrieved.fold(
            onSuccess = { checks(it, reference, signerAnchors, timeLeeway, evaluatedAt) },
            onFailure = { notRetrieved(it) to null },
        )
        val token = ValidationReport.statusListToken(checks, signerTrust, evaluatedAt)
        val resolved: KmmResult<TokenStatus> = payload?.takeIf { token.decision == ValidationDecision.ACCEPTED }
            ?.let { extractTokenStatus(it.revocationList, reference, zlibService) }
            ?: KmmResult.failure(IllegalStateException("The status list token is not accepted"))
        return statusMechanismValidation(reference, token, resolved, policy)
    }

    /** The checks of a retrieved [token], and its payload if it could be decoded. */
    private suspend fun checks(
        token: StatusListToken,
        reference: RevocationListInfo,
        signerAnchors: StatusSignerAnchors,
        timeLeeway: Duration,
        evaluatedAt: Instant,
    ): Pair<StatusListTokenChecks, StatusListTokenPayload?> {
        val payload = token.parsedPayload.getOrNull()
        val parsing = catching {
            requireNotNull(payload) { "The status list token payload can not be decoded" }
            val (type, expected) = when (token) {
                is StatusListJwt -> token.value.jws.jwsHeader.type to MediaTypes.STATUSLIST_JWT
                is StatusListCwt -> token.value.protectedHeader.type to when (payload.revocationList) {
                    is StatusList -> MediaTypes.Application.STATUSLIST_CWT
                    is IdentifierList -> MediaTypes.Application.IDENTIFIERLIST_CWT
                }
            }
            // statuslist+jwt (draft-ietf-oauth-status-list-21, 5.1), application/statuslist+cwt (5.2), and
            // application/identifierlist+cwt for identifier lists
            require(type.equals(expected, ignoreCase = true)) { "Invalid type of status list token: $type" }
        }.toOutcome()
        val signature = when (token) {
            is StatusListJwt -> signatureCheck.verify(token.value.jws)
            is StatusListCwt -> signatureCheck.verify(token.value)
        }
        // The claims of the token are only authoritative once its signature verified
        val claims = payload?.takeIf { parsing == Passed && signature.outcome == Passed }
        return StatusListTokenChecks(
            retrieval = Passed,
            parsing = parsing,
            signature = signature.outcome,
            signerTrust = if (signature.outcome == Passed) {
                signerAnchors.authorize(signature.certificateChain, evaluatedAt)
            } else TrustValidation(Blocked(), signerAnchors.credentialIdentifier),
            subject = claims?.let { subject(it, reference) } ?: Blocked(),
            timeliness = claims?.let { timeliness(it, token.resolvedAt, timeLeeway, evaluatedAt) } ?: Blocked(),
        ) to payload
    }

    private fun notRetrieved(cause: Throwable) = StatusListTokenChecks(
        retrieval = Blocked(cause),
        parsing = Blocked(),
        signature = Blocked(),
        signerTrust = TrustValidation(Blocked()),
        subject = Blocked(),
        timeliness = Blocked(),
    )

    /** `sub` equals the `uri` of the reference (draft-ietf-oauth-status-list-21, 8.3 step 4.a). */
    private fun subject(payload: StatusListTokenPayload, reference: RevocationListInfo): CheckOutcome =
        if (payload.subject.string == reference.uri.string) Passed
        else Failed(IllegalArgumentException("The subject of the status list token is not the referenced URI"))

    /**
     * An expired token is rejected (draft-ietf-oauth-status-list-21, 8.3 step 4.c), and so is a token held longer
     * than its `ttl` since it was resolved, which has to be retrieved again (step 4.d). Both with [timeLeeway].
     */
    private fun timeliness(
        payload: StatusListTokenPayload,
        resolvedAt: Instant?,
        timeLeeway: Duration,
        evaluatedAt: Instant,
    ): CheckOutcome = payload.expirationTime
        ?.takeIf { it + timeLeeway < evaluatedAt }?.let { expiration ->
            Failed(
                TimelinessException(
                    message = "The status list token is expired",
                    evaluatedAt = evaluatedAt,
                    notBefore = null,
                    notAfter = expiration
                )
            )
        }
        ?: payload.timeToLive?.let { resolvedAt?.plus(it.duration) }
            ?.takeIf { it + timeLeeway < evaluatedAt }?.let { staleAt ->
                Failed(
                    TimelinessException(
                        message = "The ttl of the status list token elapsed",
                        evaluatedAt = evaluatedAt,
                        notBefore = null,
                        notAfter = staleAt
                    )
                )
            }
        ?: Passed

    private suspend fun StatusSignerAnchors.authorize(
        chain: CertificateChain?, at: Instant
    ): TrustValidation = when (this) {
        is StatusSignerAnchors.OfCredentialType -> credentialIdentifier
            ?.let { anchors.checkCredentialTrust(it, TrustPurpose.STATUS, chain, at) }
            ?: TrustValidation(
                Blocked(IllegalArgumentException("The credential type to select status anchors is ambiguous")),
            )

        is StatusSignerAnchors.OfArtifactKind -> anchors
            ?.let { catching { it() } }
            ?.fold(
                onSuccess = {
                    TrustValidation(checkTrust(chain, it, at, TrustRule.ISSUED_BY_ANCHOR), source = source)
                },
                onFailure = {
                    TrustValidation(Blocked(it), source = source)
                },
            )
            ?: TrustValidation(
                outcome = Blocked(IllegalStateException("No status list signer anchors configured")),
            )
    }

    private val StatusSignerAnchors.credentialIdentifier: String?
        get() = (this as? StatusSignerAnchors.OfCredentialType)?.credentialIdentifier

    private val StatusPolicy.signerTrust: TrustPolicy?
        get() = when (this) {
            StatusPolicy.Skip -> null
            is StatusPolicy.ValidateIfPresent -> signerTrust
            is StatusPolicy.RequireClaim -> signerTrust
        }

    private fun KmmResult<*>.toOutcome(): CheckOutcome = fold(onSuccess = { Passed }, onFailure = { Failed(it) })
}
