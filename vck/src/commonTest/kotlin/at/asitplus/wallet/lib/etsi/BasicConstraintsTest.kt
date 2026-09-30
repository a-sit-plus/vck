package at.asitplus.wallet.lib.etsi

import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.basicConstraints_2_5_29_19
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.agent.requireTrustedSigningCertificate
import at.asitplus.wallet.lib.agent.selfSignedKey
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

/**
 * Decoding the `BasicConstraints` extension and the trust rule built on it, see [basicConstraints] and
 * [isTrustedBy].
 */
val BasicConstraintsTest by matrixSuite {

    "an authority asserts BasicConstraints with cA set" {
        val ca = TestCertificateAuthority()

        ca.certificate.basicConstraints.shouldNotBeNull().certificateAuthority shouldBe true
        ca.certificate.isCertificateAuthority shouldBe true
    }

    "pathLenConstraint is decoded when the authority carries one" {
        val ca = TestCertificateAuthority(pathLength = 0)

        ca.certificate.basicConstraints.shouldNotBeNull().pathLengthConstraint shouldBe 0
    }

    "an authority omitting pathLenConstraint reports none, rather than a default" {
        TestCertificateAuthority().certificate.basicConstraints.shouldNotBeNull()
            .pathLengthConstraint.shouldBeNull()
    }

    // Absent and "present, saying not a CA" are different statements, even though neither may issue.
    "a certificate without the extension carries no constraints and is no authority" {
        val endEntity = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()

        endEntity.basicConstraints.shouldBeNull()
        endEntity.isCertificateAuthority shouldBe false
        EphemeralKeyWithSelfSignedCert().getCertificate().shouldNotBeNull()
            .isCertificateAuthority shouldBe false
    }

    // A certificate whose constraints cannot be read must not be silently treated as unconstrained.
    "a malformed BasicConstraints extension is rejected rather than ignored" {
        val malformed = TestCertificateAuthority().issue(
            extensions = listOf(
                X509CertificateExtension(
                    oid = KnownOIDs.basicConstraints_2_5_29_19,
                    critical = true,
                    value = Asn1EncapsulatingOctetString(listOf(Asn1.Bool(true))),
                )
            )
        ).getCertificate().shouldNotBeNull()

        runCatching { malformed.basicConstraints }.exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "BasicConstraints"
    }

    "a certificate issued by an authority is trusted by it" {
        val ca = TestCertificateAuthority()
        val issued = ca.issue().getCertificate().shouldNotBeNull()

        issued.isTrustedBy(listOf(ca.certificate)).isSuccess shouldBe true
    }

    // RFC 5280 section 4.2.1.9: without cA set, the key "MUST NOT be used to verify certificate signatures".
    // The signature below is perfectly valid, so only the constraint stands between a document signer on a
    // trust list and it issuing certificates for anything.
    "an anchor that is not a certificate authority cannot have issued anything" {
        val notAnAuthority = TestCertificateAuthority(certificateAuthority = false)
        val issued = notAnAuthority.issue().getCertificate().shouldNotBeNull()

        issued.isIssuerOf(issued).isSuccess shouldBe false
        notAnAuthority.certificate.isIssuerOf(issued).isSuccess shouldBe true
        issued.isTrustedBy(listOf(notAnAuthority.certificate)).exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "BasicConstraints"
    }

    "a signing certificate whose anchor is not an authority is not trusted" {
        val notAnAuthority = TestCertificateAuthority(certificateAuthority = false)
        val signer = notAnAuthority.issue()
        val trusted = TrustedCertificates { setOf(notAnAuthority.certificate) }

        runCatching { listOf(signer.getCertificate()!!).requireTrustedSigningCertificate(trusted) }
            .exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "BasicConstraints"
    }

    // Nothing is being issued in the direct-trust case, so requiring the pinned certificate to be a CA would
    // reject exactly the setup that case exists for.
    "a directly trusted self-signed certificate stays trusted without being an authority" {
        val pinned = selfSignedKey()
        val certificate = pinned.getCertificate().shouldNotBeNull()
        certificate.isCertificateAuthority shouldBe false

        listOf(certificate).requireTrustedSigningCertificate(
            TrustedCertificates { setOf(certificate) }
        ) shouldBe certificate
    }

    "a directly trusted CA-issued end-entity certificate does not need to be an authority" {
        val signer = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()
        signer.isCertificateAuthority shouldBe false

        listOf(signer).requireTrustedSigningCertificate(
            TrustedCertificates { setOf(signer) }
        ) shouldBe signer
    }

    "direct trust can be disabled even for a listed end-entity certificate" {
        val signer = TestCertificateAuthority().issue().getCertificate().shouldNotBeNull()

        runCatching {
            listOf(signer).requireTrustedSigningCertificate(
                TrustedCertificates { setOf(signer) },
                allowDirectTrust = false,
            )
        }.exceptionOrNull().shouldNotBeNull()
            .message.shouldNotBeNull() shouldContain "must not be transported"
    }
}
