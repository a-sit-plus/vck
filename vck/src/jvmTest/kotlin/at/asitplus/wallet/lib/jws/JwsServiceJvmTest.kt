package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.encodeToTlv
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import kotlinx.coroutines.runBlocking
import at.asitplus.signum.supreme.Supreme
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import io.kotest.assertions.withClue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.random.Random

@OptIn(HazardousMaterials::class)
val JwsServiceJvmTest by matrixSuite {

    val configurations: List<Pair<String, Int>> =
        listOf(
            ("EC" to 256),
            ("EC" to 384),
            ("EC" to 521),
//            ("RSA" to 512), // JOSE does not allow key sizes < 2048
//            ("RSA" to 1024),
            ("RSA" to 2048),
            ("RSA" to 3072),
            ("RSA" to 4096)
        )
    val rsaVersions: MutableList<SignatureAlgorithm> = mutableListOf(
        RsaAlgorithm.withSHA256andPKCS1Padding,
        RsaAlgorithm.withSHA384andPKCS1Padding,
        RsaAlgorithm.withSHA512andPKCS1Padding,
        RsaAlgorithm.withSHA256andPSSPadding,
        RsaAlgorithm.withSHA384andPSSPadding,
        RsaAlgorithm.withSHA512andPSSPadding
    )

    configurations.forEach { thisConfiguration ->
        repeat(2) { number ->

            val algo = when (thisConfiguration.first) {
                "EC" -> when (thisConfiguration.second) {
                    256 -> EcdsaAlgorithm.withSHA256
                    384 -> EcdsaAlgorithm.withSHA384
                    521 -> EcdsaAlgorithm.withSHA512
                    else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                }

                "RSA" -> {
                    val rndIndex = Random.nextInt(rsaVersions.size)
                    rsaVersions.removeAt(rndIndex) // because tests are repeated twice this returns a random matching of hash-function to key-size
                }

                else -> throw IllegalArgumentException("Unknown Key Type") // -||-
            }

            val ephemeralKey = runBlocking { Supreme.init(); Signer.Ephemeral {
                if (algo is EcdsaAlgorithm)
                    ec {
                        curve = when (thisConfiguration.second) {
                            256 -> ECCurve.SECP_256_R_1
                            384 -> ECCurve.SECP_384_R_1
                            521 -> ECCurve.SECP_521_R_1
                            else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                        }
                        digest = curve.nativeDigest
                    }
                else
                    rsa {
                        this.bits = thisConfiguration.second
                        digest = (algo as RsaAlgorithm).digest as at.asitplus.signum.indispensable.digest.WellKnownDigest
                        padding = if (algo.parameters is RsaAlgorithm.Parameters.Pkcs1Padded) RsaAlgorithm.Padding.PKCS1 else RsaAlgorithm.Padding.PSS
                    }
            } }

            val jvmVerifier = if (algo is EcdsaAlgorithm)
                ECDSAVerifier(ephemeralKey.publicKey.toJcaPublicKey() as ECPublicKey)
            else RSASSAVerifier(ephemeralKey.publicKey.toJcaPublicKey() as RSAPublicKey)
            val jvmSigner = if (algo is EcdsaAlgorithm)
                ECDSASigner(ephemeralKey.jcaPrivateKey as ECPrivateKey)
            else RSASSASigner(ephemeralKey.jcaPrivateKey as RSAPrivateKey)

            val jwsSigner = SignJwt<JsonPrimitive>(EphemeralKeyWithoutCert(ephemeralKey), JwsHeaderCertOrJwk())
            val verifyJwsSignatureObject = VerifyJwsObject()
            val randomPayload = JsonPrimitive(uuid4().toString())

            val testIdentifier = "$algo, ${thisConfiguration.second}, ${number + 1}"

            "$testIdentifier:" - {

                "Signed object from int. library can be verified with int. library" {
                    val signed = jwsSigner(
                        JwsContentTypeConstants.JWT, randomPayload, JsonPrimitive.serializer()
                    ).getOrThrow()
                    val selfVerify = verifyJwsSignatureObject(signed.jws)
                    withClue("$algo: Signature: ${signed.signature.encodeToTlv().toDerHexString()}") {
                        selfVerify.getOrThrow()
                    }
                }

                "Signed object from ext. library can be verified with int. library" {
                    val libHeader = JWSHeader.Builder(JWSAlgorithm(algo.toJwsAlgorithm().getOrThrow().identifier))
                        .type(JOSEObjectType("JWT"))
                        .jwk(JWK.parse(joseCompliantSerializer.encodeToString(ephemeralKey.publicKey.toJsonWebKey())))
                        .build()
                    val libObject = JWSObject(libHeader, Payload(randomPayload.content)).also {
                        it.sign(jvmSigner)
                    }
                    libObject.verify(jvmVerifier) shouldBe true

                    // Parsing to our structure verifying payload
                    val signedLibObject = libObject.serialize()
                    val parsedJwsSigned = JwsCompact(signedLibObject)
                    parsedJwsSigned.getPayload<JsonElement>()
                        .getOrThrow().jsonPrimitive.content shouldBe randomPayload.content
                    val parsedSig = parsedJwsSigned.plainSignature.encodeToString(Base64UrlStrict)

                    withClue(
                        "$algo: \nSignatures should match\n" +
                                "Ours:\n" +
                                "$parsedSig\n" +
                                "Theirs:\n" +
                                "${libObject.signature}"
                    ) {
                        parsedSig shouldBe libObject.signature.toString()
                    }

                    withClue("$algo: Signature: ${parsedJwsSigned.plainSignature.toHexString()}") {
                        verifyJwsSignatureObject(parsedJwsSigned).getOrThrow()
                    }
                }

                "Signed object from int. library can be verified with ext. library" {
                    val signed = jwsSigner(
                        JwsContentTypeConstants.JWT, randomPayload, JsonPrimitive.serializer()
                    ).getOrThrow()
                    val parsed = JWSObject.parse(signed.toString())
                        .shouldNotBeNull()
                    parsed.payload.toBytes().decodeToString() shouldBe "\"${randomPayload.content}\""
                    val result = parsed.verify(jvmVerifier)
                    withClue("$algo: Signature: ${parsed.signature}") {
                        result shouldBe true
                    }
                }
            }
        }
    }
}