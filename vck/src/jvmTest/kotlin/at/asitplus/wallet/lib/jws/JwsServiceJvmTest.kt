package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.getJcaPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import com.nimbusds.jose.jwk.JWK
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
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
                        digests= setOf(curve.nativeDigest)
                    }
                else
                    rsa {
                        this.bits = thisConfiguration.second
                    }
            }.getOrThrow()

            val jweAlgorithm = when (algo) {
                X509SignatureAlgorithm.ES256, X509SignatureAlgorithm.ES384, X509SignatureAlgorithm.ES512 -> JweAlgorithm.ECDH_ES
                X509SignatureAlgorithm.RS256, X509SignatureAlgorithm.PS256 -> JweAlgorithm.RSA_OAEP_256
                X509SignatureAlgorithm.RS384, X509SignatureAlgorithm.PS384 -> JweAlgorithm.RSA_OAEP_384
                X509SignatureAlgorithm.RS512, X509SignatureAlgorithm.PS512 -> JweAlgorithm.RSA_OAEP_512
                else -> throw IllegalArgumentException("Unknown JweAlgorithm")
            }

            val jvmVerifier =
                if (algo.isEc) ECDSAVerifier(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as ECPublicKey)
                else RSASSAVerifier(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as RSAPublicKey)
            val jvmSigner =
                if (algo.isEc) ECDSASigner(ephemeralKey.jcaPrivateKey as ECPrivateKey)
                else RSASSASigner(ephemeralKey.jcaPrivateKey as RSAPrivateKey)
            val jvmEncrypter =
                if (algo.isEc) ECDHEncrypter(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as ECPublicKey)
                else RSAEncrypter(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as RSAPublicKey)
            val jvmDecrypter =
                if (algo.isEc) ECDHDecrypter(ephemeralKey.jcaPrivateKey as ECPrivateKey)
                else RSADecrypter(ephemeralKey.jcaPrivateKey as RSAPrivateKey)


            val keyPairAdapter = EphemeralKeyWithSelfSignedCert(ephemeralKey)
            val cryptoService = DefaultCryptoService(keyPairAdapter)
            val jwsService = DefaultJwsService(cryptoService)
            val verifierJwsService = DefaultVerifierJwsService()
            val randomPayload = uuid4().toString()

            val testIdentifier = "$algo, ${thisConfiguration.second}, ${number + 1}"

            "$testIdentifier:" - {

                "Signed object from int. library can be verified with int. library" {
                    val stringPayload = vckJsonSerializer.encodeToString(randomPayload)
                    val signed =
                        jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())
                            .getOrThrow()
                    signed.shouldNotBeNull()
                    val selfVerify = verifierJwsService.verifyJwsObject(signed)
                    withClue("$algo: Signature: ${signed.signature.encodeToTlv().toDerHexString()}") {
                        selfVerify shouldBe true
                    }
                }

                "Signed object from ext. library can be verified with int. library" {
                    val stringPayload = vckJsonSerializer.encodeToString(randomPayload)
                    val libHeader = JWSHeader.Builder(JWSAlgorithm(algo.name))
                        .type(JOSEObjectType("JWT"))
                        .jwk(JWK.parse(cryptoService.keyWithCert.jsonWebKey.serialize()))
                        .build()
                    val libObject = JWSObject(libHeader, Payload(stringPayload)).also {
                        it.sign(jvmSigner)
                    }
                    libObject.verify(jvmVerifier) shouldBe true

                    // Parsing to our structure verifying payload
                    val signedLibObject = libObject.serialize()
                    val parsedJwsSigned = JwsSigned.parse(signedLibObject).getOrThrow()
                    parsedJwsSigned.payload.decodeToString() shouldBe stringPayload
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
                    val stringPayload = vckJsonSerializer.encodeToString(randomPayload)
                    val signed =
                        jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())
                            .getOrThrow()
                    signed.shouldNotBeNull()
                    val parsed = JWSObject.parse(signed.serialize())
                    parsed.shouldNotBeNull()
                    parsed.payload.toString() shouldBe stringPayload
                    val result = parsed.verify(jvmVerifier)
                    withClue("$algo: Signature: ${parsed.signature}") {
                        result shouldBe true
                    }
                }

                /**
                 * Encryption is currently only supported for EC-Keys see issue `https://github.com/a-sit-plus/kmm-vc-library/issues/29`
                 */
                if (thisConfiguration.first == "EC") {
                    "Encrypted object from ext. library can be decrypted with int. library" {
                        val stringPayload = vckJsonSerializer.encodeToString(randomPayload)
                        val libJweHeader =
                            JWEHeader.Builder(JWEAlgorithm(jweAlgorithm.identifier), EncryptionMethod.A256GCM)
                                .type(JOSEObjectType(JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON))
                                .jwk(JWK.parse(cryptoService.keyWithCert.jsonWebKey.serialize()))
                                .contentType(JwsContentTypeConstants.DIDCOMM_PLAIN_JSON)
                                .build()
                        val libJweObject = JWEObject(libJweHeader, Payload(stringPayload)).also {
                            it.encrypt(jvmEncrypter)
                        }
                        val encryptedJwe = libJweObject.serialize()

                        val parsedJwe = JweEncrypted.parse(encryptedJwe).getOrThrow()

                        val result = jwsService.decryptJweObject(parsedJwe, encryptedJwe).getOrThrow()

                        result.payload.decodeToString() shouldBe stringPayload
                    }

                    "Encrypted object from int. library can be decrypted with ext. library" {
                        val stringPayload = vckJsonSerializer.encodeToString(randomPayload)
                        val encrypted = jwsService.encryptJweObject(
                            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
                            stringPayload.encodeToByteArray(),
                            cryptoService.keyWithCert.jsonWebKey,
                            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
                            jweAlgorithm,
                            JweEncryption.A256GCM,
                        ).getOrThrow().serialize()

                        val parsed = JWEObject.parse(encrypted)
                        parsed.shouldNotBeNull()
                        parsed.payload.shouldBeNull()

                        parsed.decrypt(jvmDecrypter)
                        parsed.payload.toString() shouldBe stringPayload
                    }
                }
            }
        }
    }
})