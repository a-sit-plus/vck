package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestValidationData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.WrprcValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.registrationCertificate.isValid
import io.kotest.matchers.maps.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val WrpValidationTest by matrixSuite {

    "WRPAC + WRPRC issuance and validation round-trip" {
        val fixture = buildWrpFixture()

        WrpChainValidator().invoke(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = fixture.trustAnchors,
        ).getOrThrow() shouldBe true

        val wrpacValidation = fixture.validateWrpac().getOrThrow()
        wrpacValidation.identifierResult?.identifier shouldBe fixture.wrpIdentifier

        val result =
            fixture.validateWrprc(payload = buildWrpPayload(fixture.wrpIdentifier)).getOrNull().shouldNotBeNull()

        result.verifierInfoValidationResult.toMap().values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidationResult.toMap().values.all { it?.isValid() == true } shouldBe true
    }

    "Wrong x509 hash in clientId" {
        val fixture = buildWrpFixture()
        val clientId = "x509_hash:wrong"

        val result = WrpacValidator().invoke(
            WrpRequestValidationData(clientId = clientId, certificateChain = fixture.wrpacChain),
            certificateTrustAnchors = fixture.trustAnchors
        ).exceptionOrNull()?.message.shouldContain("x509_hash binding failed.")
    }

    "Provider certificate expired invalidates the chain" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = providerKey,
        ).getCertificate().shouldNotBeNull()

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert =
            provider.issue(subjectName = WRP_NAME, validity = 1.days, key = wrpKey).getCertificate().shouldNotBeNull()

        WrpChainValidator().invoke(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull()?.message.shouldContain("Certificate is expired")
    }

    "WRP certificate expired invalidates the chain" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            key = providerKey,
        ).getCertificate().shouldNotBeNull()

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(
            subjectName = WRP_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = wrpKey,
        ).getCertificate().shouldNotBeNull()

        WrpChainValidator().invoke(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull()?.message.shouldContain(("Certificate is expired"))
    }

    "All chain certificates expired invalidates the chain" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = providerKey,
        ).getCertificate().shouldNotBeNull()

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(
            subjectName = WRP_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = wrpKey,
        ).getCertificate().shouldNotBeNull()

        WrpChainValidator().invoke(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull()?.message.shouldContain(("Certificate is expired"))
    }

    "Self-signed WRP certificate is not accepted as part of the chain" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            key = providerKey,
        ).getCertificate().shouldNotBeNull()

        val wrpCert = EphemeralKeyWithSelfSignedCert().getCertificate().shouldNotBeNull()

        WrpChainValidator().invoke(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull()?.message.shouldContain(("is not signed by"))
    }

    "Wrong provider subject name breaks issuer linkage" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
        val providerCert = ca.issue(
            subjectName = "Provider Wrong",
            validity = 1.days,
            key = providerKey,
        ).getCertificate().shouldNotBeNull()

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert =
            provider.issue(subjectName = WRP_NAME, validity = 1.days, key = wrpKey).getCertificate().shouldNotBeNull()

        WrpChainValidator().invoke(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull()?.message.shouldContain(("is not signed by"))
    }

    "Empty trust anchors reject any chain" {
        val fixture = buildWrpFixture()

        WrpChainValidator().invoke(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = emptyList(),
        ).exceptionOrNull()?.message.shouldContain(("No trusted root certificates configured for request validation."))
    }


    "Missing certificate chain yields an exception" {
        val result = WrpacValidator().invoke(
            validationData = WrpRequestValidationData(clientId = "x509_hash:abc", certificateChain = null),
            certificateTrustAnchors = emptyList(),
        )

        result.exceptionOrNull()?.message.shouldContain(("Certificate chain null"))
    }

    "Missing client_id yields no exception" {
        val fixture = buildWrpFixture()

        val result = WrpacValidator().invoke(
            validationData = WrpRequestValidationData(clientId = null, certificateChain = fixture.wrpacChain),
            certificateTrustAnchors = fixture.trustAnchors,
        ).getOrNull()

        result.shouldNotBeNull()
    }

    "No WRP identifier attribute yields an exception" {
        val fixture = buildWrpFixture(wrpacIdentifier = null)

        val result = fixture.validateWrpac()
        result.exceptionOrNull()?.message.shouldContain(("Unable to extract access certificate identifier"))
    }

    "WRPRC validation fails when no verifierInfo is present" {
        val fixture = buildWrpFixture()
        val wrpacValidation = fixture.validateWrpac().getOrThrow()

        val result = WrprcValidator().invoke(
            accessCertValidation = wrpacValidation,
            validationData = WrpRequestValidationData(
                clientId = fixture.clientId,
                certificateChain = fixture.wrpacChain,
                verifierInfo = null,
                request = mdocDcqlRequest(),
            ),
            statusListTokenResolver = { url ->
                buildStatusListToken(url, revokedIndex = 1)
            },
            certificateTrustAnchors = fixture.trustAnchors,
        )

        result.exceptionOrNull()?.message.shouldContain(("VerifierInfo is null"))
    }

    "Single VerifierInfo with a format other than registration_cert yields exception" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            verifierInfoFormat = "some_other_format",
        )

        result.exceptionOrNull()?.message.shouldContain(("VerifierInfoValidationResult empty"))
    }

    "Wrong JWS header type fails" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            jwsType = "not-rc-wrp+jwt",
        )

        result.exceptionOrNull()?.message.shouldContain(("has invalid typ in JWS header. expected='rc-wrp+jwt', actual='not-rc-wrp+jwt'"))
    }

    "Signature from a non-matching key fails" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate().shouldNotBeNull()
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        result.exceptionOrNull()?.message.shouldContain(("Signature is cryptographically invalid"))
    }

    "Expired WRPRC payload fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = (System.now() - 60.days).epochSeconds,
            exp = (System.now() - 30.days).epochSeconds,
        )

        val result = fixture.validateWrprc(payload = payload)
        result.exceptionOrNull()?.message.shouldContain(("already expired"))
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
            iat = System.now().epochSeconds,
            exp = (System.now() + 400.days).epochSeconds,
        )

        val result = fixture.validateWrprc(payload = payload)

        result.exceptionOrNull()?.message.shouldContain(("exceeds maximum validity"))
    }

    "sub not matching the WRPAC identifier fails linkage validation" {
        val fixture = buildWrpFixture(wrpIdentifier = "WRP-${Uuid.generateV4()}")
        val payload = buildWrpPayload(wrpIdentifier = "WRP-${Uuid.generateV4()}")

        val result = fixture.validateWrprc(payload = payload).getOrThrow()

        result.verifierInfoValidationResult.all { it.value?.validLinkage == false }
    }

    "Revoked status list entry fails status validation only" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 0)

        val result = fixture.validateWrprc(payload = payload, revokedStatusIndex = 0).getOrThrow()
        result.verifierInfoValidationResult.all { it.value?.validStatusList == false }
    }

    "Requesting more attributes than the WRPRC declares fails request validation (over-asking)" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name", "family_name", "birth_date", "portrait")),
        ).getOrNull().shouldNotBeNull()

        result.verifierInfoValidationResult.values.all { it?.isValid() == true } shouldBe true
        result.requestDataValidationResult.toMap().values.single()?.isValid() shouldBe false
    }

    "Requesting a credential format the WRPRC never declared finds no match" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(
                wrpIdentifier = fixture.wrpIdentifier,
                credentials = listOf(defaultMdocCredential())
            ),
            request = sdJwtDcqlRequest(vctValue = "urn:eudi:pid:1"),
        ).getOrNull().shouldNotBeNull()

        result.requestDataValidationResult.toMap().values.single().shouldBeNull()
    }

    "Requesting only claims the WRPRC actually declares still validates" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        ).getOrNull().shouldNotBeNull()

        result.requestDataValidationResult.toMap().values.single()?.isValid() shouldBe true
    }
}
