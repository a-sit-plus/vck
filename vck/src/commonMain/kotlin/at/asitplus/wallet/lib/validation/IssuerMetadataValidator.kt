package at.asitplus.wallet.lib.validation

import at.asitplus.catching
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.ISSUER_METADATA_JWT_TYPE
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.validation.CheckOutcome.*
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock

/**
 * Validates signed credential issuer metadata (OpenID4VCI 1.0, 12.2.3) of the EUDI Wallet ecosystem, which is signed
 * with the access certificate (WRPAC) of the PID or attestation provider (ETSI TS 119 472-3 V1.1.1, 4.2), see
 * [validate].
 */
class IssuerMetadataValidator @JvmOverloads constructor(
    /**
     * Anchors of the WRPAC providers, e.g. the issuance anchors of the WRPAC providers list (`LoteProfile.WRPAC`).
     * Without them, trust in credential issuers is blocked.
     */
    private val accessCertificates: TrustedCertificates? = null,
    private val signatureCheck: SignatureCheck = SignatureCheck(),
    private val clock: Clock = Clock.System,
) {

    /**
     * Validates [signedMetadata], requested for the credential issuer identifier [credentialIssuer], under [policy].
     * The clock is read once, all checks use that time.
     *  - `parsing`: a JWS with `typ` `openidvci-issuer-metadata+jwt`, whose payload is the metadata with the claims
     *    `sub` and `iat` (OpenID4VCI 1.0, 12.2.3), signed with the certificate in `x5c` of its protected header
     *    (ETSI TS 119 472-3 V1.1.1, ISS-MDATA-ACC_CERT-4.2.2-01), which carries the identifier of a legal or natural
     *    person, as a WRPAC (ETSI TS 119 475 V1.2.1, 5.1);
     *  - `signature`: with the access certificate in `x5c` (ISS-MDATA-4.2.1-02, ISS-MDATA-ACC_CERT-4.2.2-02);
     *  - `trust`: the certificate chain leads to one of [accessCertificates], as for relying parties: "the Wallet
     *    MUST establish trust in the signer of the metadata. Otherwise, the Wallet MUST reject the signed metadata"
     *    (OpenID4VCI 1.0, 12.2.3);
     *  - `timeliness`: `iat` is not in the future, `exp`, if present, not in the past, and every certificate of the
     *    chain is valid;
     *  - `subject`: `sub` (12.2.3) and `credential_issuer` (12.2.4) are [credentialIssuer], compared as strings
     *    without normalization (12.2.4).
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
        val checks = IssuerMetadataChecks(
            parsing = catching { parsed.requireWellFormed() }.toOutcome()
                .andThen { accessCertificate.checks.parsing },
            signature = if (chain == null) {
                Failed(IllegalArgumentException("The signed metadata transports no certificate in x5c"))
            } else verification.outcome,
            trust = accessCertificate.checks.trust,
            timeliness = metadata.timeliness(TimeScope(evaluatedAt, policy.timeLeeway))
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
        val report = ValidationReport.issuerMetadata(checks, policy, evaluatedAt)
        return if (report.decision == ValidationDecision.ACCEPTED) {
            IssuerMetadataValidation(
                report = report,
                metadata = metadata,
                accessCertificate = SignedMetadataSigner(chain!!, accessCertificate.identifier!!),
            )
        } else IssuerMetadataValidation(report)
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
    }
}

/**
 * The [report] of signed credential issuer metadata, and, if it has been accepted, the [metadata] and the
 * [accessCertificate] it is signed with.
 */
data class IssuerMetadataValidation(
    val report: ValidationReport,
    val metadata: IssuerMetadata? = null,
    val accessCertificate: SignedMetadataSigner? = null,
) {
    init {
        require(report.checks is IssuerMetadataChecks) { "Report has to be an issuer metadata report" }
        require((metadata != null) == (report.decision == ValidationDecision.ACCEPTED)) {
            "The metadata is present if and only if the report is accepted"
        }
    }
}

/**
 * The access certificate (WRPAC) signed credential issuer metadata are signed with, e.g. to show the provider to the
 * user before authorization.
 */
data class SignedMetadataSigner(
    val certificateChain: CertificateChain,
    /** The identifier of the PID or attestation provider in its WRPAC, which its WRPRC is issued to. */
    val identifier: WrpacIdentifier,
)
