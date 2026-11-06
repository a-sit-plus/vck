package at.asitplus.wallet.lib.etsi

import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.FixedTimeClock
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.validation.TimelinessException
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.cert.CertificateFactory
import kotlin.time.Instant

/**
 * [VerifyLoTE] with a list as the Commission publishes it, from the resources of this test:
 * - `pid-providers-development.jws`: the list of PID providers on [LoTEStage.DEVELOPMENT], fetched from
 *   `https://development.trust.tech.ec.europa.eu/lists/eudiw/pid-providers.json` on 2026-11-06:
 *   `LoTESequenceNumber` 18, issued 2026-10-30T09:00:38Z, `NextUpdate` 2027-04-29T09:00:38Z.
 * - `TEST_SEAL_EC_DIGIT_25A_20251031-01.cer`: the certificate the Commission publishes to verify the seal on the lists
 *   of [LoTEStage.DEVELOPMENT], downloaded from the EUDI Wallet Launchpad 2026 (`https://launchpad2026.eudiw.dev`) on
 *   2026-11-06: `CN=TEST European Commission, O=European Commission, C=LU`, issued by `CommisSign - 2`, valid from
 *   2025-11-20T09:31:26Z until 2028-11-20T09:31:26Z.
 */
val VerifyLoTEPublishedListTest by matrixSuite {

    val signedLote = resource("/pid-providers-development.jws").decodeToString().trim()
    val sealCertificate = X509Certificate.decodeFromByteArray(
        CertificateFactory.getInstance("X.509")
            .generateCertificate(resource("/TEST_SEAL_EC_DIGIT_25A_20251031-01.cer").inputStream())
            .encoded
    ).shouldNotBeNull()

    fun verifier(
        at: Instant,
        signer: X509Certificate = sealCertificate
    ) = VerifyLoTE(
        trustedSigners = TrustedCertificates { setOf(signer) },
        clock = FixedTimeClock(at.toEpochMilliseconds())
    )

    "is verified with the published seal certificate" {
        val lote = verifier(Instant.parse("2026-11-06T00:00:00Z")).invoke(signedLote, null).getOrThrow()

        lote.listAndSchemeInformation.shouldNotBeNull().loTESequenceNumber shouldBe 18
        LoTEFilterService().extractIssuanceCertificates(lote, LoteProfile.PID).shouldNotBeEmpty()
    }

    "is rejected once its NextUpdate passed" {
        verifier(Instant.parse("2027-05-01T00:00:00Z")).invoke(signedLote, null)
            .exceptionOrNull().shouldBeInstanceOf<TimelinessException>()
    }

    "is rejected once its seal certificate expired" {
        verifier(Instant.parse("2028-12-01T00:00:00Z")).invoke(signedLote, null)
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "not valid"
    }

    "is rejected for a signer that is not pinned" {
        val otherSigner = EphemeralKeyWithSelfSignedCert().getCertificate().shouldNotBeNull()

        verifier(Instant.parse("2026-11-06T00:00:00Z"), signer = otherSigner).invoke(signedLote, null)
            .isFailure shouldBe true
    }
}

private fun resource(name: String): ByteArray =
    checkNotNull(VerifyLoTE::class.java.getResourceAsStream(name)) { "Missing test resource $name" }
        .use { it.readBytes() }
