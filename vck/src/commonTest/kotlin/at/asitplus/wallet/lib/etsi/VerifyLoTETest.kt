package at.asitplus.wallet.lib.etsi

import at.asitplus.etsi.ListOfTrustedEntities
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.KeyWithFixedCert
import at.asitplus.wallet.lib.agent.TrustedCertificates
import at.asitplus.wallet.lib.validation.TimelinessException
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

val VerifyLoTETest by matrixSuite {

    // A list as the Commission publishes it is verified in VerifyLoTEPublishedListTest, which loads it from a file
    "generated list" - {
        "signed by the pinned operator is verified" {
            val operator = operatorKey()

            val lote = verifier(operator).invoke(sign(operator, payload()), null).getOrThrow()

            lote.listAndSchemeInformation.shouldNotBeNull().schemeOperatorName.first().value shouldBe OPERATOR
        }

        "signed by another key is rejected" {
            verifier(operatorKey()).invoke(sign(operatorKey(), payload()), null).isFailure shouldBe true
        }

        "whose payload was replaced is rejected" {
            val operator = operatorKey()
            val signed = sign(operator, payload(sequenceNumber = 2)).split(".")
            val replaced = sign(operator, payload(sequenceNumber = 3)).split(".")
            val tampered = listOf(signed[0], replaced[1], signed[2]).joinToString(".")

            verifier(operator).invoke(tampered, null).isFailure shouldBe true
        }

        "signed by a certificate for another organization is rejected" {
            val operator = operatorKey(organization = "Someone Else")

            verifier(operator).invoke(sign(operator, payload()), null)
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "SchemeOperatorName"
        }

        "whose NextUpdate is in the past is rejected as expired" {
            val operator = operatorKey()
            val nextUpdate = Clock.System.now() - 1.days

            verifier(operator).invoke(sign(operator, payload(nextUpdate = nextUpdate)), null)
                .exceptionOrNull().shouldBeInstanceOf<TimelinessException>()
        }

        "that is closed, i.e. has no NextUpdate, is verified" {
            val operator = operatorKey()

            verifier(operator).invoke(sign(operator, payload(nextUpdate = null)), null).isSuccess shouldBe true
        }

        "with the sequence number of the list in force is verified" {
            val operator = operatorKey()
            val inForce = verifiedList(operator, sequenceNumber = 2)

            verifier(operator).invoke(sign(operator, payload(sequenceNumber = 2)), inForce).isSuccess shouldBe true
        }

        "with a lower sequence number than the list in force is rejected" {
            val operator = operatorKey()
            val inForce = verifiedList(operator, sequenceNumber = 2)

            verifier(operator).invoke(sign(operator, payload(sequenceNumber = 1)), inForce)
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "LoTESequenceNumber"
        }

        "compared to a list in force of another type is rejected" {
            val operator = operatorKey()
            val inForce = verifiedList(operator, sequenceNumber = 1, loteType = LoteProfile.WALLET.loteType)

            verifier(operator).invoke(sign(operator, payload(sequenceNumber = 2)), inForce)
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "type"
        }
    }
}

private const val OPERATOR = "Test Scheme Operator"

private suspend fun verifier(operator: KeyMaterial) =
    VerifyLoTE(trustedSigners = TrustedCertificates { setOf(operator.getCertificate()!!) })

private suspend fun verifiedList(
    operator: KeyMaterial,
    sequenceNumber: Int,
    loteType: String = LoteProfile.PID.loteType,
): ListOfTrustedEntities = verifier(operator)
    .invoke(sign(operator, payload(sequenceNumber = sequenceNumber, loteType = loteType)), null)
    .getOrThrow()

/** A key with a self-signed certificate for `C=EU, O=[organization]`, as a scheme operator seals its lists with. */
private suspend fun operatorKey(organization: String = OPERATOR): KeyMaterial {
    val key = EphemeralKeyWithoutCert()
    val algorithm = key.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow()
    val notBefore = Clock.System.now().truncateToSeconds()
    val name = listOf(
        RelativeDistinguishedName(AttributeTypeAndValue.Country(Asn1String.Printable("EU"))),
        RelativeDistinguishedName(AttributeTypeAndValue.Organization(Asn1String.UTF8(organization))),
        RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("Seal ${Random.nextInt()}"))),
    )
    val tbsCertificate = TbsCertificate(
        version = 2,
        serialNumber = Random.nextBytes(8),
        issuerName = name,
        subjectName = name,
        validFrom = Asn1Time(notBefore),
        validUntil = Asn1Time(notBefore + 1.days),
        signatureAlgorithm = algorithm,
        publicKey = key.publicKey,
    )
    val signature = key.sign(tbsCertificate.encodeToDer()).asKmmResult().getOrThrow()
    return KeyWithFixedCert(key, X509Certificate(tbsCertificate, algorithm, signature))
}

private suspend fun sign(operator: KeyMaterial, payload: String): String = JwsCompact(
    protectedHeader = JwsHeader(
        algorithm = operator.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
        certificateChain = listOf(operator.getCertificate()!!),
    ),
    payload = payload.encodeToByteArray(),
    signer = { operator.sign(it).asKmmResult().getOrThrow().rawByteArray },
).toString()

private fun payload(
    sequenceNumber: Int = 1,
    nextUpdate: Instant? = Clock.System.now() + 1.days,
    loteType: String = LoteProfile.PID.loteType,
): String {
    val issued = Clock.System.now().truncateToSeconds()
    val next = nextUpdate?.let { "\"${it.truncateToSeconds()}\"" } ?: "null"
    return """
        {"LoTE": {"ListAndSchemeInformation": {
            "LoTEVersionIdentifier": 1,
            "LoTESequenceNumber": $sequenceNumber,
            "LoTEType": "$loteType",
            "SchemeOperatorName": [{"lang": "en", "value": "$OPERATOR"}],
            "SchemeTerritory": "EU",
            "ListIssueDateTime": "$issued",
            "NextUpdate": $next
        }}}
    """.trimIndent()
}
