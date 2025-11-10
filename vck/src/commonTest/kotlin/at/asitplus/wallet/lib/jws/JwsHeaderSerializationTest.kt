package at.asitplus.wallet.lib.jws


import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.invoke
import com.benasher44.uuid.uuid4
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random
import kotlin.time.Clock

val JwsHeaderSerializationTest by testSuite {

    "Serialization contains x5c as strings" {
        val first = randomCertificate()
        val second = randomCertificate()
        val algorithm = JwsAlgorithm.Signature.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT
        val header = JwsHeader(
            algorithm = algorithm,
            keyId = kid,
            type = type,
            certificateChain = listOf(first, second)
        )

        val serialized = joseCompliantSerializer.encodeToString(header)

        serialized shouldContain """"${first.encodeToDer().encodeToString(Base64Strict)}""""
        serialized shouldContain """"${second.encodeToDer().encodeToString(Base64Strict)}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val first = randomCertificate()
        val second = randomCertificate()
        val algorithm = JwsAlgorithm.Signature.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT

        val serialized = """{
            | "alg": "${algorithm.identifier}",
            | "kid": "$kid",
            | "typ": "$type",
            | "x5c":["${first.encodeToDer().encodeToString(Base64Strict)}","${second.encodeToDer().encodeToString(Base64Strict)}"]}
            | """.trimMargin()

        val parsed = JwsHeader.deserialize(serialized).getOrThrow()

        parsed.algorithm shouldBe algorithm
        parsed.keyId shouldBe kid
        parsed.type shouldBe type
        parsed.certificateChain.shouldNotBeNull()
        parsed.certificateChain?.shouldContain(first)
        parsed.certificateChain?.shouldContain(second)
    }

}

private fun randomCertificate() = X509Certificate(
    TbsCertificate(
        serialNumber = Random.nextBytes(16),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        publicKey = ECCurve.SECP_256_R_1.getNOTCRYPTORandomPublicKey(),
        signatureAlgorithm = X509SignatureAlgorithm.ES256,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        validFrom = Asn1Time(Clock.System.now()),
        validUntil = Asn1Time(Clock.System.now()),
    ),
    X509SignatureAlgorithm.ES256,
    CryptoSignature.EC.fromRawBytes(
        ECCurve.SECP_256_R_1,
        Random.nextBytes(ECCurve.SECP_256_R_1.scalarLength.bytes.toInt() * 2)
    ),
)
fun ECCurve.getNOTCRYPTORandomNonzeroScalar() = generateSequence {
    ModularBigInteger.creatorForModulo(this.order).fromBigInteger(BigInteger.fromByteArray(Random.nextBytes(scalarLength.bytes.toInt()), Sign.POSITIVE))
}.first { !it.isZero() }
fun ECCurve.getNOTCRYPTORandomPublicKey() = getNOTCRYPTORandomNonzeroScalar().times(generator).asPublicKey()
