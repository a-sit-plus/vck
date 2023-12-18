package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.CryptoAlgorithm
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweEncrypted
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.jsonSerializer
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.*
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import kotlin.random.Random

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
    val rsaVersions: MutableList<CryptoAlgorithm> = mutableListOf(
        CryptoAlgorithm.RS256,
        CryptoAlgorithm.RS384,
        CryptoAlgorithm.RS512,
        CryptoAlgorithm.PS256,
        CryptoAlgorithm.PS384,
        CryptoAlgorithm.PS512
    )

    configurations.forEach { thisConfiguration ->
        repeat(2) { number ->
            val keyPair = KeyPairGenerator.getInstance(thisConfiguration.first).apply {
                initialize(thisConfiguration.second)
            }.genKeyPair()

            val algo = when (thisConfiguration.first) {
                "EC" -> when (thisConfiguration.second) {
                    256 -> CryptoAlgorithm.ES256
                    384 -> CryptoAlgorithm.ES384
                    521 -> CryptoAlgorithm.ES512
                    else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                }

                "RSA" -> {
                    val rndIndex = Random.nextInt(rsaVersions.size)
                    rsaVersions.removeAt(rndIndex) // because tests are repeated twice this returns a random matching of hash-function to key-size
                }

                else -> throw IllegalArgumentException("Unknown Key Type") // -||-
            }

            val jweAlgorithm = when (algo) {
                CryptoAlgorithm.ES256, CryptoAlgorithm.ES384, CryptoAlgorithm.ES512 -> JweAlgorithm.ECDH_ES
                CryptoAlgorithm.RS256, CryptoAlgorithm.PS256 -> JweAlgorithm.RSA_OAEP_256
                CryptoAlgorithm.RS384, CryptoAlgorithm.PS384 -> JweAlgorithm.RSA_OAEP_384
                CryptoAlgorithm.RS512, CryptoAlgorithm.PS512 -> JweAlgorithm.RSA_OAEP_512
                else -> throw IllegalArgumentException("Unknown JweAlgorithm")
            }

            val jvmVerifier =
                if (algo.isEc) ECDSAVerifier(keyPair.public as ECPublicKey)
                else RSASSAVerifier(keyPair.public as RSAPublicKey)
            val jvmSigner =
                if (algo.isEc) ECDSASigner(keyPair.private as ECPrivateKey)
                else RSASSASigner(keyPair.private as RSAPrivateKey)
            val jvmEncrypter =
                if (algo.isEc) ECDHEncrypter(keyPair.public as ECPublicKey)
                else RSAEncrypter(keyPair.public as RSAPublicKey)
            val jvmDecrypter =
                if (algo.isEc) ECDHDecrypter(keyPair.private as ECPrivateKey)
                else RSADecrypter(keyPair.private as RSAPrivateKey)

            val cryptoService = DefaultCryptoService(keyPair, algo)
            val jwsService = DefaultJwsService(cryptoService)
            val verifierJwsService = DefaultVerifierJwsService()
            val randomPayload = uuid4().toString()

            val testIdentifier = "$algo, ${thisConfiguration.second}, ${number + 1}"

            "$testIdentifier:" - {

                "Signed object from int. library can be verified with int. library" {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val signed =
                        jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())
                    signed.shouldNotBeNull()
                    val selfVerify = verifierJwsService.verifyJwsObject(signed)
                    withClue("$algo: Signature: ${signed.signature.serialize()}") {
                        selfVerify shouldBe true
                    }
                }

                "Signed object from ext. library can be verified with int. library" {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val libHeader = JWSHeader.Builder(JWSAlgorithm(algo.name)).type(JOSEObjectType("JWT"))
                        .keyID(cryptoService.jsonWebKey.keyId).build()
                    val libObject = JWSObject(libHeader, Payload(stringPayload)).also {
                        it.sign(jvmSigner)
                    }
                    libObject.verify(jvmVerifier) shouldBe true

                    // Parsing to our structure verifying payload
                    val signedLibObject = libObject.serialize()
                    val parsedJwsSigned = JwsSigned.parse(signedLibObject)
                    parsedJwsSigned.shouldNotBeNull()
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

                    withClue("$algo: Signature: ${parsedJwsSigned.signature.serialize()}") {
                        val result = verifierJwsService.verifyJwsObject(parsedJwsSigned)
                        result shouldBe true
                    }
                }

                "Signed object from int. library can be verified with ext. library" {
                    val stringPayload = jsonSerializer.encodeToString(randomPayload)
                    val signed =
                        jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())
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
                if(thisConfiguration.first == "EC") {
                    "Encrypted object from ext. library can be decrypted with int. library" {
                        val stringPayload = jsonSerializer.encodeToString(randomPayload)
                        val libJweHeader = JWEHeader.Builder(JWEAlgorithm(jweAlgorithm.text), EncryptionMethod.A256GCM)
                            .type(JOSEObjectType(JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON))
                            .contentType(JwsContentTypeConstants.DIDCOMM_PLAIN_JSON)
                            .keyID(cryptoService.jsonWebKey.keyId)
                            .build()
                        val libJweObject = JWEObject(libJweHeader, Payload(stringPayload)).also {
                            it.encrypt(jvmEncrypter)
                        }
                        val encryptedJwe = libJweObject.serialize()

                        val parsedJwe = JweEncrypted.parse(encryptedJwe)
                        parsedJwe.shouldNotBeNull()

                        val result = jwsService.decryptJweObject(
                            parsedJwe, encryptedJwe
                        )

                        result?.payload?.decodeToString() shouldBe stringPayload
                    }

                    "Encrypted object from int. library can be decrypted with ext. library" {
                        val stringPayload = jsonSerializer.encodeToString(randomPayload)
                        val encrypted = jwsService.encryptJweObject(
                            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
                            stringPayload.encodeToByteArray(),
                            cryptoService.jsonWebKey,
                            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
                            jweAlgorithm,
                            JweEncryption.A256GCM,
                        )

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