package at.asitplus.wallet.lib.agent.relyingParty

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpAccessCertificate
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpChainValidator
import at.asitplus.wallet.lib.agent.validation.relyingParty.WrpRequestData
import at.asitplus.wallet.lib.agent.validation.relyingParty.accessCertificate.WrpacValidator
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days

val WrpacTest by matrixSuite {

    "Wrong x509 hash in clientId" {
        val fixture = buildWrpFixture()
        val clientId = "x509_hash:wrong"

        WrpacValidator(
            WrpRequestData(
                clientId = clientId,
                accessCertificate = WrpAccessCertificate(fixture.wrpacChain),
                registrationCertificate = emptyMap(),
            ),
            certificateTrustAnchors = fixture.trustAnchors
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("x509_hash binding failed")
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

        WrpChainValidator(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("Certificate is expired")
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

        WrpChainValidator(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("Certificate is expired")
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

        WrpChainValidator(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("Certificate is expired")
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

        WrpChainValidator(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("is not signed by")
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

        WrpChainValidator(
            chain = listOf(wrpCert, providerCert),
            certificateTrustAnchors = listOf(ca.certificate()),
        ).exceptionOrNull().shouldNotBeNull().message.shouldContain("is not signed by")
    }

    "Empty trust anchors reject any chain" {
        val fixture = buildWrpFixture()

        WrpChainValidator(
            chain = fixture.wrpacChain,
            certificateTrustAnchors = emptyList(),
        ).exceptionOrNull()
            .shouldNotBeNull().message.shouldContain("No trusted root certificates configured for request validation.")
    }

    "Missing certificate chain yields an exception" {
        val result = WrpacValidator(
            validationData = WrpRequestData(
                clientId = "x509_hash:abc",
                accessCertificate = WrpAccessCertificate(null),
                registrationCertificate = emptyMap(),
            ),
            certificateTrustAnchors = emptyList(),
        )

        result.exceptionOrNull().shouldNotBeNull().message.shouldContain("certificate chain")
    }

    "Missing client_id yields no exception" {
        val fixture = buildWrpFixture()

        val result = WrpacValidator(
            validationData = WrpRequestData(
                clientId = null,
                accessCertificate = WrpAccessCertificate(fixture.wrpacChain),
                registrationCertificate = emptyMap(),
            ),
            certificateTrustAnchors = fixture.trustAnchors,
        ).getOrNull()

        result.shouldNotBeNull()
    }

    "No WRP identifier attribute yields an exception" {
        val fixture = buildWrpFixture(wrpacIdentifier = null)

        val result = fixture.validateWrpac()
        result.exceptionOrNull()
            .shouldNotBeNull().message.shouldContain(("Unable to extract access certificate identifier"))
    }
}
