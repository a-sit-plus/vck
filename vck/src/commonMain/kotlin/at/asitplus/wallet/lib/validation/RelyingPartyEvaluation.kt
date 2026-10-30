package at.asitplus.wallet.lib.validation

import at.asitplus.catchingUnwrapped
import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.sha256
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.relyingParty.InvalidRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.MissingRegistrationCertificateException
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpCwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpJwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.getWrpIdentifier
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrpCredentialRequest
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcRequestValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.TokenStatusInfo
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.etsi.isExpired
import at.asitplus.wallet.lib.etsi.isValidAt
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.decodeFromByteArray
import kotlin.time.Duration
import kotlin.time.Instant

/** The prefix of the client identifier of requests by a wallet-relying party. */
private const val X509_HASH = "x509_hash:"

/** The checks of a WRPAC, and the identifier of its leaf if it could be parsed. */
internal class AccessCertificateEvaluation(
    val checks: AccessCertificateChecks,
    val identifier: WrpacIdentifier?,
)

/**
 * Evaluates the WRPAC [chain] of a request, whose [signature] the caller verified with the leaf of [chain]:
 *  - `parsing`: the chain is present, and, if [requireIdentifier], the leaf carries the identifier of a legal or
 *    natural person (ETSI TS 119 475 V1.2.1, 5.1), which WRPRCs are linked to; the reader certificate of a relying
 *    party without WRPRCs, accepted with [RegistrationPolicy.ValidateIfPresent], need not be a WRPAC;
 *  - `trust`: every certificate is valid and issued by the next one, and the last one is or is issued by one of
 *    [anchors], see [TrustRule.CHAIN_TO_ANCHOR];
 *  - `timeliness`: every certificate is valid at [now];
 *  - `clientId`: for a JAR, the client identifier uses the prefix `x509_hash` (ETSI TS 119 472-2 V1.1.1, 6.3.1.2,
 *    OIDFVP-HAIP_COMMON_GEN_REQ-02) with the hash of the leaf (OpenID4VP 1.0, 5.9.3); not applicable without one,
 *    i.e. for mdoc reader authentication.
 */
internal suspend fun evaluateAccessCertificate(
    chain: CertificateChain?,
    signature: CheckOutcome,
    clientId: String?,
    anchors: TrustedCertificates?,
    source: String,
    now: Instant,
    requireIdentifier: Boolean = true,
): AccessCertificateEvaluation {
    if (chain.isNullOrEmpty()) {
        // A reader authentication that did not verify yields no chain, which says nothing about the certificate, and
        // an unsigned request has none
        val parsingOutcome = when (signature) {
            is Failed -> Blocked()
            NotApplicable -> NotApplicable
            else -> Failed(IllegalArgumentException("The request transports no access certificate"))
        }
        return AccessCertificateEvaluation(
            checks = AccessCertificateChecks(
                parsing = parsingOutcome,
                signature = signature,
                trust = TrustValidation(Blocked(), source = source),
                timeliness = Blocked(),
                clientId = clientId?.let { Blocked() } ?: NotApplicable,
            ),
            identifier = null,
        )
    }
    val identifier = chain.leaf.getWrpIdentifier()
    return AccessCertificateEvaluation(
        checks = AccessCertificateChecks(
            parsing = if (requireIdentifier) identifier.toOutcome() else Passed,
            signature = signature,
            trust = TrustValidation(
                outcome = checkTrust(chain, anchors?.invoke(), now, TrustRule.CHAIN_TO_ANCHOR),
                source = source,
            ),
            timeliness = chain.timeliness(now),
            clientId = clientId?.let { chain.leaf.x509HashBinding(it) } ?: NotApplicable,
        ),
        identifier = identifier.getOrNull(),
    )
}

private fun CertificateChain.timeliness(now: Instant): CheckOutcome =
    firstOrNull { !it.isValidAt(now) }?.let {
        Failed(
            TimelinessException(
                message = if (it.isExpired(now))
                    "A certificate of the chain is expired"
                else
                    "A certificate of the chain is not yet valid",
                evaluatedAt = now,
                notBefore = it.tbsCertificate.validFrom.instant,
                notAfter = it.tbsCertificate.validUntil.instant,
            )
        )
    } ?: Passed

private fun X509Certificate.x509HashBinding(clientId: String): CheckOutcome = catchingUnwrapped {
    require(clientId.startsWith(X509_HASH)) { "The client identifier does not use the prefix x509_hash" }
    val hash = encodeToDer().sha256().encodeToString(Base64UrlStrict)
    require(clientId.removePrefix(X509_HASH) == hash) { "The client identifier is not the hash of the certificate" }
}.toOutcome()

/**
 * The checks of a WRPRC except its status, which is only resolved for a WRPRC that is valid otherwise, and the
 * finer outcomes the deprecated `WrprcValidator` reports.
 */
internal class RegistrationCertificateEvaluation(
    /** Media type and certificate chain in the header. */
    val header: CheckOutcome,
    /** The claims of the payload. */
    val claims: CheckOutcome,
    val signature: CheckOutcome,
    val trust: TrustValidation,
    val timeliness: CheckOutcome,
    val linkage: CheckOutcome,
    val requestAuthorization: CheckOutcome,
    val status: TokenStatusInfo,
) {
    /** The checks, with the [status] that has been validated. */
    fun checks(status: StatusValidation) = RegistrationCertificateChecks(
        parsing = header.andThen { claims },
        signature = signature,
        trust = trust,
        timeliness = timeliness,
        status = status,
        linkage = linkage,
        requestAuthorization = requestAuthorization,
    )
}

/** What a WRPRC has to register the wallet-relying party for. */
internal sealed interface RegistrationPurpose {
    /** Requesting the credential [requests] from a wallet, as a relying party. */
    class Presentation(val requests: List<WrpCredentialRequest>) : RegistrationPurpose

    /** Issuing attestations to a wallet, as a PID or attestation provider (ETSI TS 119 472-3 V1.1.1, 4.2.3). */
    data object Issuance : RegistrationPurpose
}

/**
 * Evaluates a WRPRC of the wallet-relying party with the WRPAC [accessIdentifier], for its [purpose]:
 *  - `parsing`: `typ` is `rc-wrp+jwt` or `rc-wrp+cwt`, and the certificate chain is in `x5c` or `x5chain`
 *    (ETSI TS 119 475 V1.2.1, 5.2.2, 5.2.3); the payload has the claims the registry provides, see
 *    [requireClaims];
 *  - `signature`: with the leaf of its certificate chain;
 *  - `trust`: the chain leads to one of [anchors], see [TrustRule.CHAIN_TO_ANCHOR];
 *  - `timeliness`: `iat` is not in the future, `exp` is not in the past, and the WRPRC is valid for at most
 *    [maxValidity] (GEN-5.2.4-08: not later than 12 months after `iat`);
 *  - `linkage`: `sub` is the identifier of the WRPAC (GEN-5.2.4-02), or the WRPAC is issued to the intermediary
 *    named in `intermediary.sub`, who presents the WRPRC of the relying party it acts for (ETSI TS 119 475 V1.2.1,
 *    4.5, Table 10, Annex E; binding through CIR (EU) 2025/848, Annex V, point 3, as amended by CIR (EU)
 *    2026/1730); a WRPRC naming an intermediary also links to the WRPAC of its own subject (ARF Annex 2, RPRC_17a
 *    note a). `act.sub` of GEN-5.2.4-09 contradicts Table 10 and is not supported;
 *  - `requestAuthorization`: for [RegistrationPurpose.Presentation], every requested credential type and claim is
 *    registered, else failed with an [UnregisteredRequestException]; for [RegistrationPurpose.Issuance], one of
 *    the entitlements of attestation providers is registered (ETSI TS 119 475 V1.2.1, 4.2, A.2), as
 *    `provides_attestations` is only present for them (B.2.1).
 */
internal suspend fun evaluateRegistrationCertificate(
    certificate: WrpRegistrationCertificate,
    accessIdentifier: WrpacIdentifier?,
    purpose: RegistrationPurpose,
    anchors: TrustedCertificates?,
    source: String,
    signatureCheck: SignatureCheck,
    maxValidity: Duration,
    timeScope: TimeScope,
): RegistrationCertificateEvaluation {
    val payload = certificate.payload
    val verification = when (certificate) {
        is WrpJwtRegistrationCertificate -> signatureCheck.verify(certificate.jwsTyped.jws)
        is WrpCwtRegistrationCertificate -> signatureCheck.verify(certificate.cose)
    }
    val chain = verification.certificateChain
    val header = catchingUnwrapped {
        val type = when (certificate) {
            is WrpJwtRegistrationCertificate -> certificate.jwsTyped.jws.jwsHeader.type
            is WrpCwtRegistrationCertificate -> certificate.cose.protectedHeader.type
        }
        val expected = when (certificate) {
            is WrpJwtRegistrationCertificate -> WRPRC_JWT_TYPE
            is WrpCwtRegistrationCertificate -> WRPRC_CWT_TYPE
        }
        require(type == expected) { "The type of the WRPRC is $type, not $expected" }
        require(!chain.isNullOrEmpty()) { "The WRPRC transports no certificate chain" }
    }.toOutcome()
    return RegistrationCertificateEvaluation(
        header = header,
        claims = catchingUnwrapped { payload.requireClaims(purpose) }.toOutcome(),
        signature = verification.outcome,
        trust = TrustValidation(
            outcome = checkTrust(chain, anchors?.invoke(), timeScope.now, TrustRule.CHAIN_TO_ANCHOR),
            source = source,
        ),
        timeliness = payload.timeliness(maxValidity, timeScope),
        linkage = when {
            accessIdentifier == null -> Blocked(IllegalStateException("The identifier of the WRPAC is unknown"))
            payload.isLinkedTo(accessIdentifier) -> Passed
            payload.intermediary != null -> Failed(
                IllegalArgumentException(
                    "Neither the sub nor the intermediary of the WRPRC is the identifier of the WRPAC"
                )
            )

            else -> Failed(IllegalArgumentException("The sub of the WRPRC is not the identifier of the WRPAC"))
        },
        requestAuthorization = catchingUnwrapped {
            when (purpose) {
                is RegistrationPurpose.Presentation -> requireRegistered(purpose.requests, payload)
                RegistrationPurpose.Issuance -> require(
                    payload.entitlements.any { it in WrpConstants.ATTESTATION_PROVIDER_ENTITLEMENTS }
                ) { "The WRPRC does not entitle the provider to issue attestations" }
            }
        }.toOutcome(),
        status = TokenStatusInfo.from(
            payload.status.statusList.let { StatusListInfo(it.idx, UniformResourceIdentifier(it.uri)) }
        ),
    )
}

/**
 * Whether this WRPRC links to the WRPAC with [accessIdentifier]: it is issued to the subject of the WRPAC, or names
 * it as the intermediary, see `linkage` of [evaluateRegistrationCertificate].
 */
internal fun WrpPayload.isLinkedTo(accessIdentifier: WrpacIdentifier): Boolean =
    accessIdentifier.identifier == subjectIdentifier || accessIdentifier.identifier == intermediary?.sub

/**
 * Whether the WRPAC with [accessIdentifier] is not issued to the subject of this WRPRC, but to the intermediary it
 * names, who presents it for the relying party it acts for (ETSI TS 119 475 V1.2.1, 4.5, Table 10).
 */
internal fun WrpPayload.isPresentedByIntermediary(accessIdentifier: WrpacIdentifier): Boolean =
    subjectIdentifier != accessIdentifier.identifier && intermediary?.sub == accessIdentifier.identifier

/**
 * The status of the WRPRC of [evaluation], only resolved for a WRPRC that is valid otherwise, as for credentials
 * (draft-ietf-oauth-status-list-21, 8.3); its signer has to be authorized by [anchors] (ETSI TS 119 475 V1.2.1,
 * 6.2.6.2).
 */
internal suspend fun registrationStatus(
    evaluation: RegistrationCertificateEvaluation,
    policy: ValidationPolicy,
    now: Instant,
    statusValidator: StatusValidator,
    anchors: TrustedCertificates?,
): StatusValidation {
    if (policy.status != StatusPolicy.Skip && !evaluation.meetsWithoutStatus(policy)) {
        return StatusValidation(
            claim = Blocked(IllegalStateException("The status of an invalid WRPRC is not resolved")),
            agreement = NotApplicable,
        )
    }
    return statusValidator.validate(
        status = evaluation.status,
        signerAnchors = StatusSignerAnchors.OfArtifactKind(anchors, REGISTRATION_STATUS_SIGNERS),
        policy = policy.status,
        timeLeeway = policy.timeLeeway,
        evaluatedAt = now,
    )
}

/**
 * Whether [registrationStatus] retrieves a status list for [evaluation], i.e. may wait for the network: only for a
 * WRPRC that is valid otherwise, under a [policy] that checks the status, with a [statusValidator] that resolves it.
 * Otherwise [registrationStatus] decides without retrieving anything.
 */
internal fun registrationStatusIsRetrieved(
    evaluation: RegistrationCertificateEvaluation,
    policy: ValidationPolicy,
    statusValidator: StatusValidator,
): Boolean = policy.status != StatusPolicy.Skip && statusValidator.resolvesStatus &&
        evaluation.meetsWithoutStatus(policy)

/** Whether [this] meets [policy] in every check but the status, which is resolved only then. */
private fun RegistrationCertificateEvaluation.meetsWithoutStatus(policy: ValidationPolicy): Boolean =
    checks(StatusValidation(NotApplicable, emptyList(), NotApplicable)).meets(policy.copy(status = StatusPolicy.Skip))

private const val REGISTRATION_STATUS_SIGNERS = "WRPRC status list signers"

internal const val WRPRC_JWT_TYPE = "rc-wrp+jwt"
internal const val WRPRC_CWT_TYPE = "rc-wrp+cwt"

/**
 * The payload includes the fields the registry provides (ETSI TS 119 475 V1.2.1, 5.2.4, GEN-5.2.4-01, Table 7),
 * as far as [WrpPayload] cannot enforce them: an entitlement of A.2 (GEN-5.2.4-03), `provides_attestations` only
 * for attestation providers (B.2.1), the `policy_id` of a WRPRC (6.1.3), and, for
 * [RegistrationPurpose.Presentation], the `purpose` and `credentials` of a service provider (GEN-5.2.4-06,
 * Table 9). Value constraints of claims are not evaluated, so a WRPRC with them is not supported for presentation:
 * authorizing its paths would widen a value-restricted registration.
 */
private fun WrpPayload.requireClaims(purpose: RegistrationPurpose) {
    require(entitlements.any { it in WrpConstants.ENTITLEMENTS }) { "The WRPRC has no entitlement of A.2" }
    require(providesAttestations == null || entitlements.any { it in WrpConstants.ATTESTATION_PROVIDER_ENTITLEMENTS }) {
        "The WRPRC provides attestations without the entitlement of an attestation provider"
    }
    if (purpose is RegistrationPurpose.Presentation) {
        requireNotNull(this.purpose) { "The WRPRC has no purpose" }
        val credentials = requireNotNull(this.credentials) { "The WRPRC has no credentials" }
        require(credentials.none { credential -> credential.claim.orEmpty().any { it.values != null } }) {
            "WRPRC claim values are not supported for authorization"
        }
    }
    require(policyId.contains(WrpConstants.POLICY_IDENTIFIER)) {
        "The WRPRC lacks the policy identifier ${WrpConstants.POLICY_IDENTIFIER}"
    }
}

private fun WrpPayload.timeliness(maxValidity: Duration, timeScope: TimeScope): CheckOutcome = with(timeScope) {
    fun failed(message: String) = Failed(TimelinessException(message, now, notBefore = iat, notAfter = exp))
    val expires = exp
    when {
        iat.isTooLate() -> failed("The WRPRC is issued in the future")
        expires != null && expires.isTooEarly() -> failed("The WRPRC is expired")
        expires != null && expires - iat > maxValidity -> failed("The WRPRC is valid for longer than $maxValidity")
        else -> Passed
    }
}

private suspend fun requireRegistered(requests: List<WrpCredentialRequest>, payload: WrpPayload) {
    val unregistered = requests.map { request -> WrprcRequestValidator(request, payload).getOrThrow() }
        .filterNot { it.second.isValid() }
    if (unregistered.isNotEmpty()) throw UnregisteredRequestException(unregistered)
}

/**
 * Parses the only registration certificate in [this], keeping the cause in the exception if it can not be parsed.
 */
internal fun Collection<VerifierInfo>.parseSingleRegistrationCertificate(): JwsCompactTyped<WrpPayload> {
    val registrationCertificates = filter { it.format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true) }
    if (registrationCertificates.isEmpty()) {
        throw MissingRegistrationCertificateException("No WRPRC in verifier_info")
    }
    val registrationCertificate = registrationCertificates.singleOrNull()
        ?: throw InvalidRegistrationCertificateException(
            "Request must contain exactly one WRPRC, but contains ${registrationCertificates.size}"
        )
    return catchingUnwrapped { parseRegistrationCertificateJwt(registrationCertificate.stringData()) }.getOrElse {
        throw InvalidRegistrationCertificateException("Could not parse WRPRC", it)
    }
}

/**
 * Parses the JWT of a `registration_cert` in `verifier_info` or `issuer_info`, given as the base64url encoding of its
 * compact serialization (ETSI TS 119 472-2 V1.1.1 OIDFVP-HAIP_COMMON_RO_REQ-09, RO-16 in later versions), or as the
 * compact serialization itself, as OpenID4VP 1.0 (5.1) allows and verifiers like the EUDI reference implementation send.
 */
internal fun parseRegistrationCertificateJwt(data: String): JwsCompactTyped<WrpPayload> =
    if (data.contains('.')) {
        JwsCompactTyped<WrpPayload>(data)
    } else {
        val decoded = catchingUnwrapped { data.decodeToByteArray(Base64UrlStrict).decodeToString() }.getOrElse {
            throw IllegalArgumentException("The WRPRC is neither a compact JWS nor its base64url encoding", it)
        }
        require(decoded.contains('.')) { "The base64url-encoded WRPRC is no compact JWS" }
        JwsCompactTyped<WrpPayload>(decoded)
    }

/** ETSI TS 119 472-2 V1.1.1 OIDFVP-HAIP_COMMON_RO_REQ-09: the registration certificate is given as a string. */
internal fun VerifierInfo.stringData(): String = when (val data = data) {
    is VerifierInfo.Data.StringData -> data.value
    is VerifierInfo.Data.ObjectData -> throw IllegalArgumentException("$format data must be a string, but is an object")
}

/** The payload of a WRPRC in CWT format, transported as `euWrprc` (ETSI TS 119 475 V1.2.1, 5.2.3). */
internal fun parseWrprcCose(euWrprc: CoseSigned<ByteArray>): WrpPayload {
    val type = euWrprc.protectedHeader.type ?: throw IllegalArgumentException("Missing typ header in euWrprc.")
    require(type == WRPRC_CWT_TYPE) { "Invalid typ header in euWrprc: expected '$WRPRC_CWT_TYPE', got '$type'." }
    val payloadBytes = euWrprc.payload ?: throw IllegalStateException("euWrprc payload not found.")
    return coseCompliantSerializer.decodeFromByteArray<WrpPayload>(bytes = payloadBytes)
}
