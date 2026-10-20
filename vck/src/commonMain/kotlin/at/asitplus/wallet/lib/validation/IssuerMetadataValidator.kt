package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.csc.api.serializers.Base64X509CertificateSerializer
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.ISSUER_METADATA_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpJwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Validates signed credential issuer metadata (OpenID4VCI 1.0, 12.2.3) of the EUDI Wallet ecosystem, which is signed
 * with the access certificate (WRPAC) of the PID or attestation provider, and carries its registration certificate
 * (WRPRC) in `issuer_info` (ETSI TS 119 472-3 V1.1.1, 4.2), see
 * [validate].
 */
class IssuerMetadataValidator @JvmOverloads constructor(
    /**
     * Anchors of the WRPAC providers, e.g. the issuance anchors of the WRPAC providers list (`LoteProfile.WRPAC`).
     * Without them, trust in credential issuers is blocked.
     */
    private val accessCertificates: TrustedCertificates? = null,
    /**
     * Anchors of the WRPRC providers, e.g. of the registrars. Without them, trust in a WRPRC is blocked, which
     * rejects metadata carrying one.
     */
    private val registrationCertificates: TrustedCertificates? = null,
    /** Anchors of the signers of the status lists of WRPRCs. */
    private val registrationStatus: TrustedCertificates? = null,
    /** Resolves and validates the status of WRPRCs. Without a resolver, their status is blocked. */
    private val statusValidator: StatusValidator = StatusValidator(),
    private val signatureCheck: SignatureCheck = SignatureCheck(),
    /** A WRPRC expires not later than 12 months after its issuance (ETSI TS 119 475 V1.2.1, GEN-5.2.4-08). */
    private val maxRegistrationValidity: Duration = 365.days,
    private val clock: Clock = Clock.System,
) {

    /**
     * Validates [signedMetadata], requested for the credential issuer identifier [credentialIssuer], under [policy].
     * The clock is read once, all checks use that time.
     *  - `parsing`: a JWS with `typ` `openidvci-issuer-metadata+jwt`, whose payload is the metadata with the claims
     *    `sub` and `iat` (OpenID4VCI 1.0, 12.2.3);
     *  - `signature`: with the key the JWS asserts, the leaf of its `x5c` or a `jwk`, see [SignatureCheck]; whether
     *    that key is an access certificate is a matter of `trust`;
     *  - `trust`: the metadata are signed with the certificate in `x5c` of the protected header (ETSI TS 119 472-3
     *    V1.1.1, ISS-MDATA-ACC_CERT-4.2.2-01), which carries the identifier of a legal or natural person, as a WRPAC
     *    (ETSI TS 119 475 V1.2.1, 5.1), and whose chain leads to one of [accessCertificates], as for relying
     *    parties: "the Wallet MUST establish trust in the signer of the metadata. Otherwise, the Wallet MUST reject
     *    the signed metadata" (OpenID4VCI 1.0, 12.2.3);
     *  - `timeliness`: `iat` is not in the future, `exp`, if present, not in the past, and every certificate of the
     *    chain is valid;
     *  - `subject`: `sub` (12.2.3) and `credential_issuer` (12.2.4) are [credentialIssuer], compared as strings
     *    without normalization (12.2.4);
     *  - `registration`: `issuer_info` is present (ETSI TS 119 472-3 V1.1.1, ISS-MDATA-REG_CERT-4.2.3-01), with
     *    exactly one `registration_cert`, a JWT (-04 to -06): "One of the elements in the issuer_info array
     *    parameter shall contain the PID/EAA Provider's registration certificate" (-04, as adapted by CIR (EU)
     *    2026/1731, Annex XI, which voids the `registrar_dataset` of -07 to -13).
     *
     * So metadata outside of the EUDI Wallet ecosystem, e.g. signed with a `jwk` and without `issuer_info`, pass
     * `parsing`, `signature`, and `subject`, and are reported as not trusted and not registered, see
     * [IssuerMetadataValidation.untrustedMetadata].
     *
     * The WRPRC is a child report, see [RegistrationCertificateChecks]: validated as for relying parties,
     * issued to the identifier of the WRPAC (GEN-5.2.4-02), trusted through [registrationCertificates], with its
     * status, and registering the provider with an entitlement of attestation providers (ETSI TS 119 475 V1.2.1,
     * 4.2, A.2).
     */
    suspend fun validate(
        signedMetadata: String,
        credentialIssuer: String,
        policy: ValidationPolicy,
    ): IssuerMetadataValidation {
        val evaluatedAt = clock.now()
        val parsed = catching { JwsCompactTyped<IssuerMetadata>(signedMetadata) }.getOrElse {
            val checks = IssuerMetadataChecks(
                parsing = Failed(it),
                signature = Blocked(),
                trust = TrustValidation(Blocked(), source = ACCESS_CERTIFICATE_PROVIDERS),
                timeliness = Blocked(),
                subject = Blocked(),
                registration = Blocked(),
            )
            return IssuerMetadataValidation(ValidationReport.issuerMetadata(checks, policy, evaluatedAt))
        }
        val metadata = parsed.payload
        val verification = signatureCheck.verify(parsed.jws)
        val chain = verification.certificateChain
        // Without x5c, there is no access certificate whose parsing and timeliness could be checked
        val accessCertificate = chain?.let {
            evaluateAccessCertificate(
                chain = it,
                signature = verification.outcome,
                clientId = null,
                anchors = accessCertificates,
                source = ACCESS_CERTIFICATE_PROVIDERS,
                now = evaluatedAt,
            )
        }
        val timeScope = TimeScope(evaluatedAt, policy.timeLeeway)
        val registration = catching { metadata.registrationCertificate() }
        val certificate = registration.getOrNull()
        val registrationCertificate = certificate?.let {
            validateRegistrationCertificate(it, accessCertificate?.identifier, policy, timeScope)
        }
        val checks = IssuerMetadataChecks(
            parsing = catching { parsed.requireWellFormed() }.toOutcome(),
            signature = verification.outcome,
            trust = accessCertificate?.trustInSigner() ?: TrustValidation(
                outcome = Failed(IllegalArgumentException("The metadata are not signed with an access certificate")),
                source = ACCESS_CERTIFICATE_PROVIDERS,
            ),
            timeliness = metadata.timeliness(timeScope)
                .andThen { accessCertificate?.checks?.timeliness ?: Passed },
            subject = catching {
                require(metadata.subject == credentialIssuer) {
                    "sub ${metadata.subject} is not the credential issuer $credentialIssuer"
                }
                require(metadata.credentialIssuer == credentialIssuer) {
                    "credential_issuer ${metadata.credentialIssuer} is not the credential issuer $credentialIssuer"
                }
            }.toOutcome(),
            registration = registration.toOutcome(),
        )
        val report = ValidationReport.issuerMetadata(checks, policy, evaluatedAt, registrationCertificate)
        val untrustedMetadata = metadata.takeIf { checks.signature == Passed && checks.subject == Passed }
        val untrustedRegistration = certificate?.payload?.takeIf {
            (registrationCertificate?.checks as? RegistrationCertificateChecks)?.parsing == Passed
        }
        return if (report.decision == ValidationDecision.ACCEPTED) {
            IssuerMetadataValidation(
                report = report,
                metadata = metadata,
                untrustedMetadata = untrustedMetadata,
                untrustedRegistration = untrustedRegistration,
                // The required WRPRC is only accepted if linked to the identifier of a WRPAC, whatever the policy
                issuer = ValidatedCredentialIssuer(
                    accessCertificateChain = checkNotNull(chain) { "Accepted metadata without x5c" },
                    identifier = checkNotNull(accessCertificate?.identifier) { "Accepted WRPAC without identifier" },
                    registrationCertificate = registration.getOrThrow().payload,
                ),
            )
        } else IssuerMetadataValidation(
            report = report,
            untrustedMetadata = untrustedMetadata,
            untrustedRegistration = untrustedRegistration,
        )
    }

    /**
     * Trust in the signer of the metadata, which has to be a WRPAC carrying the identifier of the provider: a
     * certificate without one is not trusted, whether or not its chain leads to an anchor.
     */
    private fun AccessCertificateEvaluation.trustInSigner(): TrustValidation =
        if (checks.parsing == Passed) checks.trust else checks.trust.copy(outcome = checks.parsing)

    private suspend fun validateRegistrationCertificate(
        certificate: WrpJwtRegistrationCertificate,
        accessIdentifier: WrpacIdentifier?,
        policy: ValidationPolicy,
        timeScope: TimeScope,
    ): ValidationReport {
        val evaluation = evaluateRegistrationCertificate(
            certificate = certificate,
            accessIdentifier = accessIdentifier,
            purpose = RegistrationPurpose.Issuance,
            anchors = registrationCertificates,
            source = REGISTRATION_CERTIFICATE_PROVIDERS,
            signatureCheck = signatureCheck,
            maxValidity = maxRegistrationValidity,
            timeScope = timeScope,
        )
        val status = registrationStatus(evaluation, policy, timeScope.now, statusValidator, registrationStatus)
        return ValidationReport.registrationCertificate(evaluation.checks(status), policy, timeScope.now)
    }

    /**
     * The only `registration_cert` of `issuer_info`, a JWT (ETSI TS 119 472-3 V1.1.1, ISS-MDATA-REG_CERT-4.2.3-01,
     * -04 to -06), required by -04 as adapted by CIR (EU) 2026/1731, Annex XI.
     */
    private fun IssuerMetadata.registrationCertificate(): WrpJwtRegistrationCertificate {
        val issuerInfo = requireNotNull(issuerInfo) { "The signed metadata contains no issuer_info" }
        val certificates = issuerInfo.filter { it.format == REGISTRATION_CERT_FORMAT }
        require(certificates.size == 1) {
            "issuer_info contains ${certificates.size} registration_cert elements, not one"
        }
        val data = certificates.single().data
        require(data is JsonPrimitive && data.isString) { "The registration_cert is no JWT" }
        return WrpJwtRegistrationCertificate(JwsCompactTyped<WrpPayload>(data.content))
    }

    private fun JwsCompactTyped<IssuerMetadata>.requireWellFormed() {
        require(jws.jwsHeader.type == ISSUER_METADATA_JWT_TYPE) { "invalid typ: ${jws.jwsHeader.type}" }
        requireNotNull(payload.subject) { "The signed metadata contains no sub" }
        requireNotNull(payload.issuedAt) { "The signed metadata contains no iat" }
    }

    private fun IssuerMetadata.timeliness(timeScope: TimeScope): CheckOutcome = with(timeScope) {
        val issuedAt = issuedAt ?: return Blocked()
        val expiration = expiration
        fun failed(message: String) =
            Failed(TimelinessException(message, now, notBefore = issuedAt, notAfter = expiration))
        when {
            issuedAt.isTooLate() -> failed("issuedAt in future: $issuedAt")
            expiration != null && expiration.isTooEarly() -> failed("expiration in past: $expiration")
            else -> Passed
        }
    }

    private companion object {
        const val ACCESS_CERTIFICATE_PROVIDERS = "WRPAC providers"
        const val REGISTRATION_CERTIFICATE_PROVIDERS = "WRPRC providers"
    }
}

/**
 * The [report] of signed credential issuer metadata, with the report of its WRPRC as child, if any, and, if it has
 * been accepted, the [metadata] and the [issuer].
 */
data class IssuerMetadataValidation(
    val report: ValidationReport,
    val metadata: IssuerMetadata? = null,
    val issuer: ValidatedCredentialIssuer? = null,
    /**
     * The metadata, whatever the decision of [report], if their `signature` and `subject` passed: they are signed
     * with the key they assert, the certificate in `x5c` or a `jwk`, and are the ones of the requested credential
     * issuer, but this signer may not be trusted, nor be a registered provider. So they are no more trustworthy than
     * unsigned metadata: use them only to continue after showing the report to the user, never as an accepted
     * credential issuer.
     */
    val untrustedMetadata: IssuerMetadata? = null,
    /**
     * What the WRPRC in `issuer_info` says, whatever the decision of [report], if its `parsing` passed, e.g. to show
     * the name and the registered attestations of a provider next to the warning that it is not trusted. It is not
     * verified unless [issuer] is present: its signer may not be trusted, nor its status valid, nor it be issued to
     * the signer of the metadata, so use it only to show it to the user, marked as such.
     */
    val untrustedRegistration: WrpPayload? = null,
) {
    init {
        require(report.checks is IssuerMetadataChecks) { "Report has to be an issuer metadata report" }
        require((metadata != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "The metadata is present if and only if the report is accepted"
        }
        require(metadata == null || metadata == untrustedMetadata) {
            "Accepted metadata are the untrusted metadata too"
        }
        require(issuer == null || issuer.registrationCertificate == untrustedRegistration) {
            "The registration certificate of an accepted issuer is the untrusted registration too"
        }
    }
}

/**
 * A PID or attestation provider whose signed metadata passed every required check, e.g. to show it to the user
 * before authorization. Serializable, so that a wallet can keep it during the authorization in the browser.
 */
@Serializable
data class ValidatedCredentialIssuer(
    /** The access certificate (WRPAC) the metadata are signed with. */
    val accessCertificateChain: List<@Serializable(with = Base64X509CertificateSerializer::class) X509Certificate>,
    /** The identifier of the provider in its WRPAC, which its WRPRC is issued to. */
    val identifier: WrpacIdentifier,
    /** What the provider is registered for, from the WRPRC in its metadata. */
    val registrationCertificate: WrpPayload,
)
