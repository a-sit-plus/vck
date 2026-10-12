package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
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
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
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
 *  - `parsing`: the chain is present, and the leaf carries the identifier of a legal or natural person
 *    (ETSI TS 119 475 V1.2.1, 5.1);
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
): AccessCertificateEvaluation {
    if (chain.isNullOrEmpty()) {
        // A reader authentication that did not verify yields no chain, which says nothing about the certificate
        val missing = if (signature is Failed)
            Blocked()
        else
            Failed(IllegalArgumentException("The request transports no access certificate"))
        return AccessCertificateEvaluation(
            checks = AccessCertificateChecks(
                parsing = missing,
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
            parsing = identifier.toOutcome(),
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

private fun X509Certificate.x509HashBinding(clientId: String): CheckOutcome = catching {
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

/**
 * Evaluates a WRPRC of a request by the wallet-relying party with the WRPAC [accessIdentifier], for the credential
 * [requests] it covers:
 *  - `parsing`: `typ` is `rc-wrp+jwt` or `rc-wrp+cwt`, and the certificate chain is in `x5c` or `x5chain`
 *    (ETSI TS 119 475 V1.2.1, 5.2.2, 5.2.3); the payload has the claims the registry provides, see
 *    [requireClaims];
 *  - `signature`: with the leaf of its certificate chain;
 *  - `trust`: the chain leads to one of [anchors], see [TrustRule.CHAIN_TO_ANCHOR];
 *  - `timeliness`: `iat` is not in the future, `exp` is not in the past, and the WRPRC is valid for at most
 *    [maxValidity] (GEN-5.2.4-08: not later than 12 months after `iat`);
 *  - `linkage`: `sub` is the identifier of the WRPAC (GEN-5.2.4-02);
 *  - `requestAuthorization`: every requested credential type and claim is registered, else failed with an
 *    [UnregisteredRequestException].
 */
internal suspend fun evaluateRegistrationCertificate(
    certificate: WrpRegistrationCertificate,
    accessIdentifier: WrpacIdentifier?,
    requests: List<WrpCredentialRequest>,
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
    val header = catching {
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
        claims = catching { payload.requireClaims() }.toOutcome(),
        signature = verification.outcome,
        trust = TrustValidation(
            outcome = checkTrust(chain, anchors?.invoke(), timeScope.now, TrustRule.CHAIN_TO_ANCHOR),
            source = source,
        ),
        timeliness = payload.timeliness(maxValidity, timeScope),
        linkage = when {
            accessIdentifier == null -> Blocked(IllegalStateException("The identifier of the WRPAC is unknown"))
            accessIdentifier.identifier == payload.subjectIdentifier -> Passed
            else -> Failed(IllegalArgumentException("The sub of the WRPRC is not the identifier of the WRPAC"))
        },
        requestAuthorization = catching { requireRegistered(requests, payload) }.toOutcome(),
        status = TokenStatusInfo.from(
            payload.status.statusList.let { StatusListInfo(it.idx, UniformResourceIdentifier(it.uri)) }
        ),
    )
}

internal const val WRPRC_JWT_TYPE = "rc-wrp+jwt"
internal const val WRPRC_CWT_TYPE = "rc-wrp+cwt"

/**
 * The payload includes the fields the registry provides (ETSI TS 119 475 V1.2.1, 5.2.4, GEN-5.2.4-01, Table 7),
 * as far as they can be missing in [WrpPayload]: `name`, `srv_description`, and the `policy_id` of a WRPRC
 * (6.1.3), and the credentials it is registered for (EUDI TS5). Value constraints of claims are not evaluated, so a
 * WRPRC with them is not supported: authorizing its paths would widen a value-restricted registration.
 */
private fun WrpPayload.requireClaims() {
    requireNotNull(name) { "The WRPRC has no name" }
    require(srvDescription.isNotEmpty()) { "The WRPRC has no srv_description" }
    require(credentials.isNotEmpty()) { "The WRPRC has no credentials" }
    require(credentials.none { credential -> credential.claim.any { it.values != null } }) {
        "WRPRC claim values are not supported for authorization"
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
