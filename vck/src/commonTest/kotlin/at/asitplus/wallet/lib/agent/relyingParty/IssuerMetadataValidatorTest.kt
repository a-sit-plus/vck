package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpCredential
import at.asitplus.etsi.relyingParty.WrpCredentialMeta
import at.asitplus.etsi.relyingParty.WrpIdentifier
import at.asitplus.etsi.relyingParty.WrpMultiLangString
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpRegistrarDataset
import at.asitplus.openid.IssuerInfo
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.ISSUER_METADATA_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRAR_DATASET_FORMAT
import at.asitplus.openid.OpenIdConstants.IssuerInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.IssuerMetadataChecks
import at.asitplus.wallet.lib.validation.IssuerMetadataValidation
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.RegistrationCertificateChecks
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TokenStatusException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

val IssuerMetadataValidatorTest by matrixSuite {

    "metadata signed with a trusted access certificate are accepted, with the signer" {
        val fixture = buildWrpFixture()

        fixture.validate(fixture.signedMetadata()).apply {
            report.decision shouldBe ACCEPTED
            report.children.shouldBeEmpty()
            metadata.shouldNotBeNull().credentialIssuer shouldBe CREDENTIAL_ISSUER
            untrustedMetadata shouldBe metadata
            issuer.shouldNotBeNull().apply {
                identifier shouldBe WrpacIdentifier.WrpacLegalIdentifier(fixture.wrpIdentifier)
                accessCertificateChain shouldBe fixture.wrpacChain
                registrarDataset shouldBe registrarDataset()
                registrationCertificate.shouldBeNull()
            }
        }
    }

    "metadata with the WRPRC of an attestation provider are accepted, with what it is registered for" {
        val fixture = buildWrpFixture()
        val wrprc = fixture.issuerWrprc()

        fixture.validate(fixture.signedMetadata(metadata(issuerInfo = issuerInfo(wrprc)))).apply {
            report.decision shouldBe ACCEPTED
            report.children.single().decision shouldBe ACCEPTED
            issuer.shouldNotBeNull().registrationCertificate.shouldNotBeNull()
                .providesAttestations shouldBe PROVIDED_ATTESTATIONS
        }
    }

    "a WRPRC without an entitlement of attestation providers is rejected" {
        val fixture = buildWrpFixture()
        val serviceProvider = "https://uri.etsi.org/19475/Entitlement/Service_Provider"
        val wrprc = fixture.issuerWrprc(entitlements = listOf(serviceProvider))

        fixture.validate(fixture.signedMetadata(metadata(issuerInfo = issuerInfo(wrprc)))).apply {
            report.decision shouldBe REJECTED
            registrationChecks().requestAuthorization.shouldBeInstanceOf<CheckOutcome.Failed>()
            metadata.shouldBeNull()
            // signed for the credential issuer, so a wallet may continue after warning the user
            untrustedMetadata.shouldNotBeNull().credentialIssuer shouldBe CREDENTIAL_ISSUER
        }
    }

    "a revoked WRPRC is rejected with its status, and the metadata are still authenticated" {
        val fixture = buildWrpFixture()
        val validator = IssuerMetadataValidator(
            accessCertificates = fixture.trustAnchors,
            registrationCertificates = fixture.trustAnchors,
            statusValidator = StatusValidator(StatusListTokenResolver { buildStatusListToken(it, revokedIndex = 1) }),
        )
        // the status list tokens are signed by a key without certificate, so their signers are not authorized
        val statusPolicy = policy.copy(status = StatusPolicy.RequireClaim(signerTrust = TrustPolicy.IntegrityOnly))
        suspend fun signed(statusListIdx: Int) = fixture.signedMetadata(
            metadata(issuerInfo = issuerInfo(fixture.issuerWrprc(statusListIdx = statusListIdx)))
        )

        validator.validate(signed(statusListIdx = 0), CREDENTIAL_ISSUER, statusPolicy).report.decision shouldBe ACCEPTED
        validator.validate(signed(statusListIdx = 1), CREDENTIAL_ISSUER, statusPolicy).apply {
            report.decision shouldBe REJECTED
            checks().apply {
                signature shouldBe CheckOutcome.Passed
                subject shouldBe CheckOutcome.Passed
            }
            registrationChecks().status.mechanisms.shouldBeSingleton().first().outcome
                .shouldBeInstanceOf<CheckOutcome.Failed>().throwable.shouldBeInstanceOf<TokenStatusException>()
            metadata.shouldBeNull()
            issuer.shouldBeNull()
            untrustedMetadata.shouldNotBeNull().credentialIssuer shouldBe CREDENTIAL_ISSUER
        }
    }

    "a WRPRC issued to another provider, or of an untrusted registrar, is rejected" {
        val fixture = buildWrpFixture()
        val other = fixture.issuerWrprc(identifier = "another-provider")

        fixture.validate(fixture.signedMetadata(metadata(issuerInfo = issuerInfo(other))))
            .registrationChecks().linkage.shouldBeInstanceOf<CheckOutcome.Failed>()
        IssuerMetadataValidator(accessCertificates = fixture.trustAnchors).validate(
            fixture.signedMetadata(metadata(issuerInfo = issuerInfo(fixture.issuerWrprc()))),
            CREDENTIAL_ISSUER,
            policy,
        ).apply {
            report.decision shouldBe REJECTED
            registrationChecks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            untrustedMetadata.shouldNotBeNull()
        }
    }

    "issuer_info has to contain one registrar_dataset and at most one registration_cert, as JWT" {
        val fixture = buildWrpFixture()
        val wrprc = fixture.issuerWrprc()
        val dataset = IssuerInfo(REGISTRAR_DATASET_FORMAT, registrarDatasetJson())
        val certificate = IssuerInfo(REGISTRATION_CERT_FORMAT, JsonPrimitive(wrprc))
        val invalid = listOf(
            null,
            emptyList(),
            listOf(certificate),
            listOf(dataset, dataset),
            listOf(IssuerInfo(REGISTRAR_DATASET_FORMAT, JsonObject(emptyMap()))),
            listOf(IssuerInfo(REGISTRAR_DATASET_FORMAT, JsonPrimitive("not an object"))),
            listOf(dataset, certificate, certificate),
            listOf(dataset, IssuerInfo(REGISTRATION_CERT_FORMAT, buildJsonObject { })),
            listOf(dataset, IssuerInfo(REGISTRATION_CERT_FORMAT, JsonPrimitive("not-a-jws"))),
        )

        invalid.forEach {
            fixture.validate(fixture.signedMetadata(metadata(issuerInfo = it))).checks().parsing
                .shouldBeInstanceOf<CheckOutcome.Failed>()
        }
    }

    "without anchors, trust is blocked, and with an empty list of WRPAC providers it fails" {
        val fixture = buildWrpFixture()
        val signed = fixture.signedMetadata()

        IssuerMetadataValidator().validate(signed, CREDENTIAL_ISSUER, policy).apply {
            report.decision shouldBe REJECTED
            checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            metadata.shouldBeNull()
            untrustedMetadata.shouldNotBeNull()
        }
        IssuerMetadataValidator(accessCertificates = { emptySet() }).validate(signed, CREDENTIAL_ISSUER, policy)
            .apply {
                checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
                untrustedMetadata.shouldNotBeNull()
            }
    }

    "metadata of an untrusted signer are reported, so the wallet can warn, if the policy does not require trust" {
        val fixture = buildWrpFixture()
        val relaxed = policy.copy(trust = TrustPolicy.IntegrityOnly)

        IssuerMetadataValidator(accessCertificates = { emptySet() })
            .validate(fixture.signedMetadata(), CREDENTIAL_ISSUER, relaxed).apply {
                report.decision shouldBe ACCEPTED
                checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
            }
    }

    "metadata signed with a certificate of another provider is rejected" {
        val fixture = buildWrpFixture()
        val foreign = buildWrpFixture()

        fixture.validate(foreign.signedMetadata()).checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "metadata whose signature does not verify with the access certificate is rejected" {
        val fixture = buildWrpFixture()
        val signed = fixture.signedMetadata(key = EphemeralKeyWithoutCert())

        fixture.validate(signed).apply {
            checks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
            untrustedMetadata.shouldBeNull()
        }
    }

    "metadata signed without x5c is rejected" {
        val fixture = buildWrpFixture()
        val signed = SignJwt<IssuerMetadata>(fixture.wrpKey, JwsHeaderJwk())(
            ISSUER_METADATA_JWT_TYPE, metadata(), IssuerMetadata.serializer()
        ).getOrThrow().toString()

        fixture.validate(signed).apply {
            checks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
            checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            untrustedMetadata.shouldBeNull()
        }
    }

    "metadata signed with a self-signed certificate is rejected" {
        val fixture = buildWrpFixture()
        val selfSigned = EphemeralKeyWithSelfSignedCert()
        val signed = SignJwt<IssuerMetadata>(selfSigned, JwsHeaderCertOrJwk())(
            ISSUER_METADATA_JWT_TYPE, metadata(), IssuerMetadata.serializer()
        ).getOrThrow().toString()

        fixture.validate(signed).report.decision shouldBe REJECTED
    }

    "metadata of another credential issuer is rejected" {
        val fixture = buildWrpFixture()

        fixture.validate(fixture.signedMetadata(metadata(subject = "https://other.example.com"))).apply {
            checks().subject.shouldBeInstanceOf<CheckOutcome.Failed>()
            untrustedMetadata.shouldBeNull()
        }
        fixture.validate(fixture.signedMetadata(metadata(credentialIssuer = "https://other.example.com")))
            .checks().subject.shouldBeInstanceOf<CheckOutcome.Failed>()
        // compared without normalization (OpenID4VCI 1.0, 12.2.4)
        fixture.validate(fixture.signedMetadata(), credentialIssuer = "$CREDENTIAL_ISSUER/")
            .checks().subject.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "metadata with a wrong typ, without iat, or that can not be parsed are rejected" {
        val fixture = buildWrpFixture()

        fixture.validate(fixture.signedMetadata(type = "JWT")).checks().parsing
            .shouldBeInstanceOf<CheckOutcome.Failed>()
        fixture.validate(fixture.signedMetadata(metadata().copy(issuedAt = null))).checks().parsing
            .shouldBeInstanceOf<CheckOutcome.Failed>()
        fixture.validate("not-a-jws").checks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "the access certificate has to carry the identifier of the provider" {
        val fixture = buildWrpFixture(wrpacIdentifier = null)

        fixture.validate(fixture.signedMetadata()).checks().parsing.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "expired metadata and metadata issued in the future are rejected" {
        val fixture = buildWrpFixture()
        val now = Clock.System.now().truncateToSeconds()

        fixture.validate(fixture.signedMetadata(metadata(issuedAt = now - 2.hours).copy(expiration = now - 1.hours)))
            .checks().timeliness.shouldBeInstanceOf<CheckOutcome.Failed>()
            .throwable.shouldBeInstanceOf<TimelinessException>()
        fixture.validate(fixture.signedMetadata(metadata(issuedAt = now + 1.hours)))
            .checks().timeliness.shouldBeInstanceOf<CheckOutcome.Failed>()
    }
}

private const val CREDENTIAL_ISSUER = "https://issuer.example.com"

private val policy = ValidationPolicy(
    trust = TrustPolicy.RequireAuthorizedSigner,
    status = StatusPolicy.Skip,
    timeLeeway = 5.minutes,
    requireTimeliness = true,
)

private fun IssuerMetadataValidation.checks() = report.checks.shouldBeInstanceOf<IssuerMetadataChecks>()

private suspend fun WrpFixture.validate(signed: String, credentialIssuer: String = CREDENTIAL_ISSUER) =
    IssuerMetadataValidator(accessCertificates = trustAnchors, registrationCertificates = trustAnchors)
        .validate(signed, credentialIssuer, policy)

private fun IssuerMetadataValidation.registrationChecks() =
    report.children.single().checks.shouldBeInstanceOf<RegistrationCertificateChecks>()

private val PROVIDED_ATTESTATIONS = listOf(
    WrpCredential(format = "dc+sd-jwt", meta = WrpCredentialMeta(vctValues = listOf("urn:eudi:pid:1"))),
)

private fun registrarDataset() = WrpRegistrarDataset(
    identifier = listOf(WrpIdentifier(type = "http://data.europa.eu/eudi/id/LEI", identifier = "LEI-PROVIDER")),
    srvDescription = listOf(WrpMultiLangString(lang = "en", content = "Issues PIDs")),
    registryURI = "https://registrar.example.com",
    providesAttestations = PROVIDED_ATTESTATIONS,
)

private fun registrarDatasetJson() =
    joseCompliantSerializer.encodeToJsonElement(WrpRegistrarDataset.serializer(), registrarDataset())

/** `issuer_info` with the registration information, and [wrprc] if any (ETSI TS 119 472-3 V1.1.1, 4.2.3). */
private fun issuerInfo(wrprc: String? = null) = listOfNotNull(
    IssuerInfo(REGISTRAR_DATASET_FORMAT, registrarDatasetJson()),
    wrprc?.let { IssuerInfo(REGISTRATION_CERT_FORMAT, JsonPrimitive(it)) },
)

/** A WRPRC of this fixture for a provider of PIDs, signed by the WRPRC provider of the fixture. */
private suspend fun WrpFixture.issuerWrprc(
    identifier: String = wrpIdentifier,
    entitlements: List<String> = listOf(WrpConstants.ENTITLEMENT_PID_PROVIDER),
    statusListIdx: Int = 0,
): String {
    val payload: WrpPayload = buildWrpPayload(identifier, credentials = emptyList(), statusListIdx = statusListIdx)
        .copy(entitlements = entitlements, providesAttestations = PROVIDED_ATTESTATIONS)
    return signWrprc(wrprcSigningKeyMaterial, payload)
}

private fun metadata(
    credentialIssuer: String = CREDENTIAL_ISSUER,
    subject: String = CREDENTIAL_ISSUER,
    issuedAt: Instant = Clock.System.now().truncateToSeconds(),
    issuerInfo: List<IssuerInfo>? = issuerInfo(),
) = IssuerMetadata(
    credentialIssuer = credentialIssuer,
    credentialEndpointUrl = "$CREDENTIAL_ISSUER/credential",
    supportedCredentialConfigurations = emptyMap(),
    subject = subject,
    issuedAt = issuedAt,
    issuerInfo = issuerInfo,
)

/** [metadata] signed by [key] with the WRPAC chain of this fixture in `x5c`, as OpenID4VCI 1.0, 12.2.3. */
private suspend fun WrpFixture.signedMetadata(
    metadata: IssuerMetadata = metadata(),
    key: KeyMaterial = wrpKey,
    type: String = ISSUER_METADATA_JWT_TYPE,
    chain: List<X509Certificate> = wrpacChain,
): String = SignJwt<IssuerMetadata>(key, { header, _ -> header.copy(certificateChain = chain) })(
    type = type,
    payload = metadata,
    serializer = IssuerMetadata.serializer(),
).getOrThrow().toString()
