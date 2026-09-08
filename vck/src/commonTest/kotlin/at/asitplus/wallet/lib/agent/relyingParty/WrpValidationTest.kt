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
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
val WrpValidationTest by matrixSuite {

    "WRPAC + WRPRC issuance and validation round-trip" {
        val fixture = buildWrpFixture()

        WrpChainValidator.validateChain(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = fixture.trustAnchors,
        ) shouldBe true

        val wrpacValidation = fixture.validateWrpac()!!
        wrpacValidation.chainValid shouldBe true
        wrpacValidation.hashValid shouldBe true
        wrpacValidation.identifierResult?.identifier shouldBe fixture.wrpIdentifier

        val result = fixture.validateWrprc(payload = buildWrpPayload(fixture.wrpIdentifier))

        result?.verifierInfoValidationResult?.values?.all { it?.isValid() == true } shouldBe true
        result?.requestDataValidationResult?.values?.all { it?.isValid() == true } shouldBe true
    }

    "Wrong x509 hash in clientId" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val wrpacProviderKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = wrpacProviderKey)
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            key = wrpacProviderKey,
        ).getCertificate()!!

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(
            subjectName = WRP_NAME,
            validity = 1.days,
            key = wrpKey,
        ).getCertificate()!!

        val chain = listOf(wrpCert, providerCert)
        val certificateTrustAnchors = listOf(ca.certificate())

        val clientId = "x509_hash:wrong"

        val result = WrpacValidator.validate(
            WrpRequestValidationData(clientId = clientId, certificateChain = chain),
            certificateTrustAnchors,
        )!!
        result.chainValid shouldBe true
        result.hashValid shouldBe false
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
        ).getCertificate()!!

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(subjectName = WRP_NAME, validity = 1.days, key = wrpKey).getCertificate()!!

        WrpChainValidator.validateChain(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ) shouldBe false
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
        ).getCertificate()!!

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(
            subjectName = WRP_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = wrpKey,
        ).getCertificate()!!

        WrpChainValidator.validateChain(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ) shouldBe false
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
        ).getCertificate()!!

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(
            subjectName = WRP_NAME,
            validity = 1.days,
            validFrom = System.now() - 2.days,
            key = wrpKey,
        ).getCertificate()!!

        WrpChainValidator.validateChain(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ) shouldBe false
    }

    "Self-signed WRP certificate is not accepted as part of the chain" {
        val caKey = EphemeralKeyWithoutCert()
        val ca = TestCertificateAuthority(name = CA_NAME, key = caKey)

        val providerKey = EphemeralKeyWithoutCert()
        val provider = TestCertificateAuthority(name = WRPAC_PROVIDER_NAME, key = providerKey)
        val providerCert = ca.issue(
            subjectName = WRPAC_PROVIDER_NAME,
            validity = 1.days,
            key = providerKey,
        ).getCertificate()!!

        val wrpCert = EphemeralKeyWithSelfSignedCert().getCertificate()!!

        WrpChainValidator.validateChain(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ) shouldBe false
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
        ).getCertificate()!!

        val wrpKey = EphemeralKeyWithoutCert()
        val wrpCert = provider.issue(subjectName = WRP_NAME, validity = 1.days, key = wrpKey).getCertificate()!!

        WrpChainValidator.validateChain(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ) shouldBe false
    }

    "Empty trust anchors reject any chain" {
        val fixture = buildWrpFixture()

        WrpChainValidator.validateChain(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = emptyList(),
        ) shouldBe false
    }


    "Missing certificate chain yields no WRPAC validation result" {
        val result = WrpacValidator.validate(
            validationData = WrpRequestValidationData(clientId = "x509_hash:abc", certificateChain = null),
            certificateTrustAnchors = emptyList(),
        )

        result.shouldBeNull()
    }

    "Missing client_id yields no WRPAC validation result" {
        val fixture = buildWrpFixture()

        val result = WrpacValidator.validate(
            validationData = WrpRequestValidationData(clientId = null, certificateChain = fixture.wrpacChain),
            certificateTrustAnchors = fixture.trustAnchors,
        )

        result.shouldBeNull()
    }

    "No WRP identifier attribute yields a null identifier result" {
        val fixture = buildWrpFixture(wrpacIdentifier = null)

        val result = fixture.validateWrpac()!!

        result.chainValid shouldBe true
        result.hashValid shouldBe true
        result.identifierResult.shouldBeNull()
    }

    "WRPRC validation fails when no verifierInfo is present" {
        val fixture = buildWrpFixture()
        val wrpacValidation = fixture.validateWrpac()!!

        val result = WrprcValidator.validate(
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

        result.shouldBeNull()
    }

    "VerifierInfo with a format other than registration_cert is skipped" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            verifierInfoFormat = "some_other_format",
        )

        result?.verifierInfoValidationResult?.values?.single().shouldBeNull()
    }

    "Wrong JWS header type fails header validation only" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            jwsType = "not-rc-wrp+jwt",
        )

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.headerValid shouldBe false
        verifierInfoResult.chainValid shouldBe true
        verifierInfoResult.signatureValid shouldBe true
        verifierInfoResult.payloadValid shouldBe true
        verifierInfoResult.linkageValid shouldBe true
        verifierInfoResult.statusValid shouldBe true
        verifierInfoResult.isValid() shouldBe false
    }

    "Signature from a non-matching key fails signature validation only" {
        val fixture = buildWrpFixture()
        val realCertificate = fixture.wrprcSigningKeyMaterial.getCertificate()!!
        val mismatchedSigner = KeyWithFixedCert(EphemeralKeyWithoutCert(), realCertificate)

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            signingKeyMaterial = mismatchedSigner,
        )

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.signatureValid shouldBe false
        verifierInfoResult.chainValid shouldBe true
        verifierInfoResult.headerValid shouldBe true
        verifierInfoResult.isValid() shouldBe false
    }

    "Expired WRPRC payload fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = (System.now() - 60.days).epochSeconds,
            exp = (System.now() - 30.days).epochSeconds,
        )

        val result = fixture.validateWrprc(payload = payload)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.payloadValid shouldBe false
        verifierInfoResult.isValid() shouldBe false
    }

    "WRPRC payload missing intendedUseId still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, intendedUseId = null)

        val result = fixture.validateWrprc(payload = payload)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.payloadValid shouldBe true
        verifierInfoResult.isValid() shouldBe true
    }

    "WRPRC payload missing exp still validates" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, exp = null)

        val result = fixture.validateWrprc(payload = payload)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.payloadValid shouldBe true
        verifierInfoResult.isValid() shouldBe true
    }

    "WRPRC payload with exp more than 12 months after iat fails payload validation" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(
            fixture.wrpIdentifier,
            iat = System.now().epochSeconds,
            exp = (System.now() + 400.days).epochSeconds,
        )

        val result = fixture.validateWrprc(payload = payload)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.payloadValid shouldBe false
        verifierInfoResult.isValid() shouldBe false
    }

    "sub not matching the WRPAC identifier fails linkage validation" {
        val fixture = buildWrpFixture(wrpIdentifier = "WRP-${Uuid.generateV4()}")
        val payload = buildWrpPayload(wrpIdentifier = "WRP-${Uuid.generateV4()}")

        val result = fixture.validateWrprc(payload = payload)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.linkageValid shouldBe false
        verifierInfoResult.payloadValid shouldBe true
        verifierInfoResult.isValid() shouldBe false
    }

    "Revoked status list entry fails status validation only" {
        val fixture = buildWrpFixture()
        val payload = buildWrpPayload(fixture.wrpIdentifier, statusListIdx = 0)

        val result = fixture.validateWrprc(payload = payload, revokedStatusIndex = 0)

        val verifierInfoResult = result?.verifierInfoValidationResult?.values?.single()!!
        verifierInfoResult.statusValid shouldBe false
        verifierInfoResult.signatureValid shouldBe true
        verifierInfoResult.chainValid shouldBe true
        verifierInfoResult.headerValid shouldBe true
        verifierInfoResult.payloadValid shouldBe true
        verifierInfoResult.linkageValid shouldBe true
        verifierInfoResult.isValid() shouldBe false
    }

    "Requesting more attributes than the WRPRC declares fails request validation (over-asking)" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name", "family_name", "birth_date", "portrait")),
        )

        result?.verifierInfoValidationResult?.values?.all { it?.isValid() == true } shouldBe true
        result?.requestDataValidationResult?.values?.single()?.isValid() shouldBe false
    }

    "Requesting a credential format the WRPRC never declared finds no match" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(
                wrpIdentifier = fixture.wrpIdentifier,
                credentials = listOf(defaultMdocCredential())
            ),
            request = sdJwtDcqlRequest(vctValue = "urn:eudi:pid:1"),
        )

        result?.requestDataValidationResult?.values?.single().shouldBeNull()
    }

    "Requesting only claims the WRPRC actually declares still validates" {
        val fixture = buildWrpFixture()

        val result = fixture.validateWrprc(
            payload = buildWrpPayload(fixture.wrpIdentifier),
            request = mdocDcqlRequest(claimNames = listOf("given_name")),
        )

        result?.requestDataValidationResult?.values?.single()?.isValid() shouldBe true
    }
}
