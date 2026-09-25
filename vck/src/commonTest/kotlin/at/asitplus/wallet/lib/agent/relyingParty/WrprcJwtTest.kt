package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.etsi.relyingParty.WrpClaim
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAccessCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val WrprcJwtTest by matrixSuite {

    "Issuance and validation round-trip" {
        val fixture = buildWrpFixture()

        WrpChainValidator(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = fixture.trustAnchors,
        ).getOrThrow() shouldBe true

        val wrpacValidation = fixture.validateWrpac().getOrThrow()
        wrpacValidation.identifierResult?.identifier shouldBe fixture.wrpIdentifier

        val result =
            fixture.validateWrprc(payload = buildWrpPayload(fixture.wrpIdentifier)).getOrThrow()

        result.certificateValidation.toMap().values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidation.toMap().values.all { it?.isValid() == true } shouldBe true
    }

    "WRPRC validation with no registration certificate present succeeds with empty results" {
        val fixture = buildWrpFixture()
        val wrpacValidation = fixture.validateWrpac().getOrThrow()

        val result = WrprcValidator()(
            identifierResult = wrpacValidation.identifierResult,
            validationData = WrpRequestData(
                clientId = fixture.clientId,
                accessCertificate = WrpAccessCertificate(fixture.wrpacChain),
                registrationCertificate = emptyMap(),
            ),
            tokenStatusResolver = TokenStatusResolverImpl({ statusListUrl ->
                buildStatusListToken(statusListUrl, revokedIndex = 1)
            }),
            certificateTrustAnchors = fixture.trustAnchors,
        )

        result.exceptionOrNull().shouldNotBeNull().message.shouldContain("No registration certificates to verify")
    }

    "Wrong JWS header type fails" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            jwsType = "not-rc-wrp+jwt",
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validHeader shouldBe false
    }

    "WRPRC signed under an untrusted CA fails chain validation" {
        val fixture = buildWrpFixture()
        val untrustedSigner = TestCertificateAuthority(name = "Untrusted CA").issue(subjectName = WRPRC_PROVIDER_NAME)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = untrustedSigner,
        ).getOrThrow()

        val validation = result.certificateValidation.values.single().shouldNotBeNull()
        validation.validChain shouldBe false
        validation.validSignature shouldBe true
    }

    "Signature from a non-matching key fails" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validSignature shouldBe false
    }

    "Expired WRPRC payload fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = Instant.fromEpochSeconds((System.now() - 60.days).epochSeconds),
            exp = Instant.fromEpochSeconds((System.now() - 30.days).epochSeconds),
        )

        val result = fixture.validateWrprc(payload = payload)
        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validPayload shouldBe false
    }

    "WRPRC payload missing optional intendedUseId still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, intendedUseId = null)

        val result = fixture.validateWrprc(payload = payload)
        result.isSuccess.shouldBe(true)
    }

    "WRPRC payload missing optional exp still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, exp = null)

        val result = fixture.validateWrprc(payload = payload)
        result.isSuccess.shouldBe(true)

    }

    "WRPRC payload with exp more than 12 months after iat fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = Instant.fromEpochSeconds(System.now().epochSeconds),
            exp = Instant.fromEpochSeconds((System.now() + 400.days).epochSeconds),
        )

        val result = fixture.validateWrprc(payload = payload)

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validPayload shouldBe false
    }

    "sub not matching the WRPAC identifier fails linkage validation" {
        val fixture = buildWrpFixture(wrpIdentifier = "WRP-${Uuid.generateV4()}")
        val payload = buildWrpPayload(wrpIdentifier = "WRP-${Uuid.generateV4()}")

        val result = fixture.validateWrprc(payload = payload).getOrThrow()

        result.certificateValidation.all { it.value?.validLinkage == false }.shouldBe(true)
    }

    "Revoked status list entry fails status validation only" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 0)

        val result = fixture.validateWrprc(payload = payload, revokedStatusIndex = 0).getOrThrow()
        result.certificateValidation.all { it.value?.validStatusList == false }.shouldBe(true)
    }

    "Requesting more attributes than the WRPRC declares fails request validation (over-asking)" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name", "family_name", "birth_date", "portrait")),
        ).getOrThrow()

        result.certificateValidation.values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidation.toMap().values.single().isValid() shouldBe false
    }

    "Requesting a credential format the WRPRC never declared finds no match" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(
                wrpIdentifier = fixture.wrpIdentifier,
                credentials = listOf(defaultMdocCredential())
            ),
            request = sdJwtDcqlRequest(vctValue = "urn:eudi:pid:1"),
        ).getOrThrow()

        result.requestDataValidation.toMap().values.single().credentialTypeValidity.shouldBe(false)
    }

    "Requesting only claims the WRPRC actually declares still validates" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        ).getOrThrow()

        result.requestDataValidation.toMap().values.single().isValid() shouldBe true
    }

    "WRPRC with unsupported claim values does not authorize a path-only request" {
        val fixture = buildWrpFixture()
        val credential = defaultMdocCredential().copy(
            claim = listOf(WrpClaim(path = listOf(DEFAULT_DOCTYPE, "given_name"), values = listOf("Alice")))
        )

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier, credentials = listOf(credential)),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        )

        result.getOrThrow().certificateValidation.values.single().shouldNotBeNull().validPayload shouldBe false
    }
}
