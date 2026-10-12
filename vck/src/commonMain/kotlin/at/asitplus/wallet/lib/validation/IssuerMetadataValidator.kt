package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpRegistrarDataset
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.ISSUER_METADATA_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRAR_DATASET_FORMAT
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRegistrationCertificate.WrpJwtRegistrationCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Validates signed credential issuer metadata (OpenID4VCI 1.0, 12.2.3) of the EUDI Wallet ecosystem, which is signed
 * with the access certificate (WRPAC) of the PID or attestation provider, and carries its registration information
 * and possibly its registration certificate (WRPRC) in `issuer_info` (ETSI TS 119 472-3 V1.1.1, 4.2), see
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
     *    `sub` and `iat` (OpenID4VCI 1.0, 12.2.3), signed with the certificate in `x5c` of its protected header
     *    (ETSI TS 119 472-3 V1.1.1, ISS-MDATA-ACC_CERT-4.2.2-01), which carries the identifier of a legal or natural
     *    person, as a WRPAC (ETSI TS 119 475 V1.2.1, 5.1); `issuer_info` is present (ISS-MDATA-REG_CERT-4.2.3-01),
     *    with one `registrar_dataset`, a JSON object with `identifier`, `srvDescription`, `registryURI`, and
     *    `providesAttestations` (-07 to -13), and at most one `registration_cert`, a JWT (-04 to -06);
     *  - `signature`: with the access certificate in `x5c` (ISS-MDATA-4.2.1-02, ISS-MDATA-ACC_CERT-4.2.2-02);
     *  - `trust`: the certificate chain leads to one of [accessCertificates], as for relying parties: "the Wallet
     *    MUST establish trust in the signer of the metadata. Otherwise, the Wallet MUST reject the signed metadata"
     *    (OpenID4VCI 1.0, 12.2.3);
     *  - `timeliness`: `iat` is not in the future, `exp`, if present, not in the past, and every certificate of the
     *    chain is valid;
     *  - `subject`: `sub` (12.2.3) and `credential_issuer` (12.2.4) are [credentialIssuer], compared as strings
     *    without normalization (12.2.4).
     *
     * The WRPRC, if any, is a child report, see [RegistrationCertificateChecks]: validated as for relying parties,
     * issued to the identifier of the WRPAC (GEN-5.2.4-02), trusted through [registrationCertificates], with its
     * status, and registering the provider with an entitlement of attestation providers (ETSI TS 119 475 V1.2.1,
     * 4.2, A.2). The registration information itself is signed with the metadata, but not by the registrar, so its
     * content is not checked against the WRPRC or the registry.
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
            )
            return IssuerMetadataValidation(ValidationReport.issuerMetadata(checks, policy, evaluatedAt))
        }
        val metadata = parsed.payload
        val verification = signatureCheck.verify(parsed.jws)
        val chain = verification.certificateChain
        val accessCertificate = evaluateAccessCertificate(
            chain = chain,
            signature = verification.outcome,
            clientId = null,
            anchors = accessCertificates,
            source = ACCESS_CERTIFICATE_PROVIDERS,
            now = evaluatedAt,
        )
        val timeScope = TimeScope(evaluatedAt, policy.timeLeeway)
        val registration = catching { metadata.registration() }
        val registrationCertificate = registration.getOrNull()?.certificate?.let {
            validateRegistrationCertificate(it, accessCertificate.identifier, policy, timeScope)
        }
        val checks = IssuerMetadataChecks(
            parsing = catching { parsed.requireWellFormed() }.toOutcome()
                .andThen { registration.toOutcome() }
                .andThen { accessCertificate.checks.parsing },
            signature = if (chain == null) {
                Failed(IllegalArgumentException("The signed metadata transports no certificate in x5c"))
            } else verification.outcome,
            trust = accessCertificate.checks.trust,
            timeliness = metadata.timeliness(timeScope)
                .andThen { accessCertificate.checks.timeliness },
            subject = catching {
                require(metadata.subject == credentialIssuer) {
                    "sub ${metadata.subject} is not the credential issuer $credentialIssuer"
                }
                require(metadata.credentialIssuer == credentialIssuer) {
                    "credential_issuer ${metadata.credentialIssuer} is not the credential issuer $credentialIssuer"
                }
            }.toOutcome(),
        )
        val report = ValidationReport.issuerMetadata(checks, policy, evaluatedAt, registrationCertificate)
        return if (report.decision == ValidationDecision.ACCEPTED) {
            IssuerMetadataValidation(
                report = report,
                metadata = metadata,
                issuer = ValidatedCredentialIssuer(
                    accessCertificateChain = chain!!,
                    identifier = accessCertificate.identifier!!,
                    registrarDataset = registration.getOrThrow().dataset,
                    registrationCertificate = registration.getOrThrow().certificate?.payload,
                ),
            )
        } else IssuerMetadataValidation(report)
    }

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

    private class Registration(
        val dataset: WrpRegistrarDataset,
        val certificate: WrpJwtRegistrationCertificate?,
    )

    /** The elements of `issuer_info` (ETSI TS 119 472-3 V1.1.1, 4.2.3). */
    private fun IssuerMetadata.registration(): Registration {
        val issuerInfo = requireNotNull(issuerInfo) { "The signed metadata contains no issuer_info" }
        val datasets = issuerInfo.filter { it.format == REGISTRAR_DATASET_FORMAT }
        require(datasets.size == 1) { "issuer_info contains ${datasets.size} registrar_dataset elements, not one" }
        val data = datasets.single().data
        require(data is JsonObject && data.isNotEmpty()) { "The registrar_dataset is no non-empty JSON object" }
        val dataset = joseCompliantSerializer.decodeFromJsonElement(WrpRegistrarDataset.serializer(), data)
        require(dataset.identifier.isNotEmpty()) { "The registrar_dataset contains no identifier" }
        require(dataset.srvDescription.isNotEmpty()) { "The registrar_dataset contains no srvDescription" }
        require(dataset.providesAttestations.isNotEmpty()) {
            "The registrar_dataset contains no providesAttestations"
        }
        val certificates = issuerInfo.filter { it.format == REGISTRATION_CERT_FORMAT }
        require(certificates.size <= 1) { "issuer_info contains ${certificates.size} registration_cert elements" }
        val certificate = certificates.singleOrNull()?.data?.let {
            require(it is JsonPrimitive && it.isString) { "The registration_cert is no JWT" }
            WrpJwtRegistrationCertificate(JwsCompactTyped<WrpPayload>(it.content))
        }
        return Registration(dataset, certificate)
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
) {
    init {
        require(report.checks is IssuerMetadataChecks) { "Report has to be an issuer metadata report" }
        require((metadata != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "The metadata is present if and only if the report is accepted"
        }
    }
}

/**
 * A PID or attestation provider whose signed metadata passed every required check, e.g. to show it to the user
 * before authorization.
 */
data class ValidatedCredentialIssuer(
    /** The access certificate (WRPAC) the metadata are signed with. */
    val accessCertificateChain: CertificateChain,
    /** The identifier of the provider in its WRPAC, which its WRPRC is issued to. */
    val identifier: WrpacIdentifier,
    /** The registration information of the provider, as the provider states it in `issuer_info`. */
    val registrarDataset: WrpRegistrarDataset,
    /** What the provider is registered for, if its metadata carry a WRPRC. */
    val registrationCertificate: WrpPayload?,
)
