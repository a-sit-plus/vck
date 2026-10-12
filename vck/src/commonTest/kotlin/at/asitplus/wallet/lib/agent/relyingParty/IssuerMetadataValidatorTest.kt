package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.ISSUER_METADATA_JWT_TYPE
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial

import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacIdentifier
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.IssuerMetadataChecks
import at.asitplus.wallet.lib.validation.IssuerMetadataValidation
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TimelinessException
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
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
            accessCertificate.shouldNotBeNull().apply {
                identifier shouldBe WrpacIdentifier.WrpacLegalIdentifier(fixture.wrpIdentifier)
                certificateChain shouldBe fixture.wrpacChain
            }
        }
    }

    "without anchors, trust is blocked, and with an empty list of WRPAC providers it fails" {
        val fixture = buildWrpFixture()
        val signed = fixture.signedMetadata()

        IssuerMetadataValidator().validate(signed, CREDENTIAL_ISSUER, policy).apply {
            report.decision shouldBe REJECTED
            checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
            metadata.shouldBeNull()
        }
        IssuerMetadataValidator(accessCertificates = { emptySet() }).validate(signed, CREDENTIAL_ISSUER, policy)
            .checks().trust.outcome.shouldBeInstanceOf<CheckOutcome.Failed>()
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

        fixture.validate(signed).checks().signature.shouldBeInstanceOf<CheckOutcome.Failed>()
    }

    "metadata signed without x5c is rejected" {
        val fixture = buildWrpFixture()
        val signed = SignJwt<IssuerMetadata>(fixture.wrpKey, JwsHeaderJwk())(
            ISSUER_METADATA_JWT_TYPE, metadata(), IssuerMetadata.serializer()
        ).getOrThrow().toString()

        fixture.validate(signed).checks().apply {
            signature.shouldBeInstanceOf<CheckOutcome.Failed>()
            trust.outcome.shouldBeInstanceOf<CheckOutcome.Blocked>()
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

        fixture.validate(fixture.signedMetadata(metadata(subject = "https://other.example.com")))
            .checks().subject.shouldBeInstanceOf<CheckOutcome.Failed>()
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
    IssuerMetadataValidator(accessCertificates = trustAnchors).validate(signed, credentialIssuer, policy)

private fun metadata(
    credentialIssuer: String = CREDENTIAL_ISSUER,
    subject: String = CREDENTIAL_ISSUER,
    issuedAt: Instant = Clock.System.now().truncateToSeconds(),
) = IssuerMetadata(
    credentialIssuer = credentialIssuer,
    credentialEndpointUrl = "$CREDENTIAL_ISSUER/credential",
    supportedCredentialConfigurations = emptyMap(),
    subject = subject,
    issuedAt = issuedAt,
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
