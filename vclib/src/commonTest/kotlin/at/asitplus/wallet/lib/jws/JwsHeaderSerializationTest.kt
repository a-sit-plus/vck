package at.asitplus.wallet.lib.jws


import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.CryptoSignature
import at.asitplus.crypto.datatypes.ECCurve
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.pki.AttributeTypeAndValue
import at.asitplus.crypto.datatypes.pki.RelativeDistinguishedName
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.random.Random

class JwsHeaderSerializationTest : FreeSpec({

    "Serialization contains x5c as strings" {
        val first = randomCertificate()
        val second = randomCertificate()
        val algorithm = JwsAlgorithm.ES256
        val kid = uuid4().toString()
        val type = JwsContentTypeConstants.JWT
        val header = JwsHeader(
            algorithm = algorithm,
            keyId = kid,
            type = type,
            certificateChain = listOf(first, second)
        )

        val serialized = header.serialize()

        serialized shouldContain """"${first.encodeToDer().encodeToString(Base64Strict)}""""
        serialized shouldContain """"${second.encodeToDer().encodeToString(Base64Strict)}""""
        serialized shouldContain """"$kid""""
    }

    "Deserialization is correct" {
        val first = randomCertificate()
        val second = randomCertificate()
        val algorithm = JwsAlgorithm.ES256
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

})

private fun randomCertificate() = X509Certificate(
    TbsCertificate(
        serialNumber = Random.nextBytes(16),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        publicKey = CryptoPublicKey.EC(ECCurve.SECP_256_R_1, Random.nextBytes(32),Random.nextBytes(32)),
        signatureAlgorithm = CryptoAlgorithm.ES256,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.Printable("Test")))),
        validFrom = Asn1Time(Clock.System.now()),
        validUntil = Asn1Time(Clock.System.now()),
    ),
    CryptoAlgorithm.ES256,
    CryptoSignature.EC.fromRawBytes(ECCurve.SECP_256_R_1, Random.nextBytes(ECCurve.SECP_256_R_1.scalarLength.bytes.toInt()*2)),
)
