package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
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
class JwsServiceJvmTest : FreeSpec({

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
    val rsaVersions: MutableList<X509SignatureAlgorithm> = mutableListOf(
        X509SignatureAlgorithm.RS256,
        X509SignatureAlgorithm.RS384,
        X509SignatureAlgorithm.RS512,
        X509SignatureAlgorithm.PS256,
        X509SignatureAlgorithm.PS384,
        X509SignatureAlgorithm.PS512
    )

    configurations.forEach { thisConfiguration ->
        repeat(2) { number ->

            val algo = when (thisConfiguration.first) {
                "EC" -> when (thisConfiguration.second) {
                    256 -> X509SignatureAlgorithm.ES256
                    384 -> X509SignatureAlgorithm.ES384
                    521 -> X509SignatureAlgorithm.ES512
                    else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                }

                "RSA" -> {
                    val rndIndex = Random.nextInt(rsaVersions.size)
                    rsaVersions.removeAt(rndIndex) // because tests are repeated twice this returns a random matching of hash-function to key-size
                }

                else -> throw IllegalArgumentException("Unknown Key Type") // -||-
            }

            val ephemeralKey = EphemeralKey {
                if (algo.isEc)
                    ec {
                        curve = when (thisConfiguration.second) {
                            256 -> ECCurve.SECP_256_R_1
                            384 -> ECCurve.SECP_384_R_1
                            521 -> ECCurve.SECP_521_R_1
                            else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                        }
                        digests = setOf(curve.nativeDigest)
                    }
                else
                    rsa {
                        this.bits = thisConfiguration.second
                    }
            }.getOrThrow()

            val jvmVerifier =
                if (algo.isEc) ECDSAVerifier(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as ECPublicKey)
                else RSASSAVerifier(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as RSAPublicKey)
            val jvmSigner =
                if (algo.isEc) ECDSASigner(ephemeralKey.jcaPrivateKey as ECPrivateKey)
                else RSASSASigner(ephemeralKey.jcaPrivateKey as RSAPrivateKey)


            val keyPairAdapter = EphemeralKeyWithoutCert(ephemeralKey)
            val cryptoService = DefaultCryptoService(keyPairAdapter)
            val jwsService = DefaultJwsService(cryptoService)
            val verifierJwsService = DefaultVerifierJwsService()
            val randomPayload = JsonPrimitive(uuid4().toString())

            val testIdentifier = "$algo, ${thisConfiguration.second}, ${number + 1}"

            "$testIdentifier:" - {

                "Signed object from int. library can be verified with int. library" {
                    val signed = jwsService.createSignedJwt(
                        JwsContentTypeConstants.JWT, randomPayload, JsonPrimitive.serializer()
                    ).getOrThrow()
                    val selfVerify = verifierJwsService.verifyJwsObject(signed)
                    withClue("$algo: Signature: ${signed.signature.encodeToTlv().toDerHexString()}") {
                        selfVerify shouldBe true
                    }
                }

                "Signed object from ext. library can be verified with int. library" {
                    val libHeader = JWSHeader.Builder(JWSAlgorithm(algo.name))
                        .type(JOSEObjectType("JWT"))
                        .jwk(JWK.parse(cryptoService.keyMaterial.jsonWebKey.serialize()))
                        .build()
                    val libObject = JWSObject(libHeader, Payload(randomPayload.content)).also {
                        it.sign(jvmSigner)
                    }
                    libObject.verify(jvmVerifier) shouldBe true

                    // Parsing to our structure verifying payload
                    val signedLibObject = libObject.serialize()
                    val parsedJwsSigned = JwsSigned.deserialize<JsonElement>(JsonElement.serializer(), signedLibObject).getOrThrow()
                    parsedJwsSigned.payload.jsonPrimitive.content shouldBe randomPayload.content
                    val parsedSig = parsedJwsSigned.signature.rawByteArray.encodeToString(Base64UrlStrict)

                    withClue(
                        "$algo: \nSignatures should match\n" +
                                "Ours:\n" +
                                "$parsedSig\n" +
                                "Theirs:\n" +
                                "${libObject.signature}"
                    ) {
                        parsedSig shouldBe libObject.signature.toString()
                    }

                    withClue("$algo: Signature: ${parsedJwsSigned.signature.encodeToTlv().toDerHexString()}") {
                        val result = verifierJwsService.verifyJwsObject(parsedJwsSigned)
                        result shouldBe true
                    }
                }

                "Signed object from int. library can be verified with ext. library" {
                    val signed = jwsService.createSignedJwt(
                        JwsContentTypeConstants.JWT, randomPayload, JsonPrimitive.serializer()
                    ).getOrThrow()
                    val parsed = JWSObject.parse(signed.serialize())
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
})