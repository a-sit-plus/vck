package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.ECCurve.*
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweEncryption.*
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A128GCMKW
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A128KW
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A192GCMKW
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A192KW
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A256GCMKW
import at.asitplus.signum.indispensable.josef.JweAlgorithm.A256KW
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_128
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_192
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_256
import at.asitplus.signum.indispensable.symmetric.SymmetricKey
import at.asitplus.signum.indispensable.symmetric.hasDedicatedMacKey
import at.asitplus.signum.indispensable.symmetric.isAuthenticated
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.signum.indispensable.symmetric.secretKey
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.AESDecrypter
import com.nimbusds.jose.crypto.AESEncrypter
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.JWK
import de.infix.testBalloon.framework.testSuite
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

@OptIn(HazardousMaterials::class, SecretExposure::class)
class JweServiceJvmTest by testSuite{

    val ecdhesConfiguration = listOf(
        EcdhesConfiguration(SECP_256_R_1, listOf(A128CBC_HS256, A128GCM)),
        EcdhesConfiguration(SECP_384_R_1, listOf(A192CBC_HS384, A192GCM)),
        EcdhesConfiguration(SECP_521_R_1, listOf(A256CBC_HS512, A256GCM)),
    )

    ecdhesConfiguration.forEach { config ->
        val ephemeralKey = EphemeralKey {
            ec {
                curve = config.curve
                digests = setOf(curve.nativeDigest)
            }
        }.getOrThrow()

        val jweAlgorithm = JweAlgorithm.ECDH_ES
        val jvmEncrypter = ECDHEncrypter(ephemeralKey.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey)
        val jvmDecrypter = ECDHDecrypter(ephemeralKey.jcaPrivateKey as ECPrivateKey)

        val keyMaterial = EphemeralKeyWithoutCert(ephemeralKey)
        val encrypter = EncryptJwe(keyMaterial)
        val decrypter = DecryptJwe(keyMaterial)
        val randomPayload = uuid4().toString()

        config.encryption.forEach { encryptionMethod ->
            "${config.curve}, ${encryptionMethod}" - {
                "Encrypted object from ext. library can be decrypted with int. library" {
                    val libJweHeader =
                        JWEHeader.Builder(JWEAlgorithm(jweAlgorithm.identifier), encryptionMethod.joseAlgorithm)
                            .type(JOSEObjectType("something"))
                            .jwk(JWK.parse(joseCompliantSerializer.encodeToString(keyMaterial.jsonWebKey)))
                            .build()
                    val libJweObject = JWEObject(libJweHeader, Payload(randomPayload))
                        .apply { encrypt(jvmEncrypter) }
                    val encryptedJwe = libJweObject.serialize()

                    val parsedJwe = JweEncrypted.deserialize(encryptedJwe).getOrThrow()
                    val result = decrypter(parsedJwe).getOrThrow()
                    result.payload shouldBe randomPayload
                }

                "Encrypted object from int. library can be decrypted with ext. library" {
                    val encrypted = encrypter(
                        JweHeader(
                            algorithm = jweAlgorithm,
                            encryption = encryptionMethod,
                        ),
                        randomPayload,
                        keyMaterial.jsonWebKey,
                    ).getOrThrow().serialize()

                    val parsed = JWEObject.parse(encrypted).shouldNotBeNull()

                    parsed.decrypt(jvmDecrypter)
                    parsed.payload.toBytes().decodeToString() shouldBe randomPayload
                }
            }
        }
    }

    val symmetricConfiguration = listOf(
        SymmetricConfiguration(A128KW, listOf(A128CBC_HS256, A128GCM)),
        SymmetricConfiguration(A192KW, listOf(A192CBC_HS384, A192GCM)),
        SymmetricConfiguration(A256KW, listOf(A256CBC_HS512, A256GCM)),
        SymmetricConfiguration(A128GCMKW, listOf(A128CBC_HS256, A128GCM)),
        SymmetricConfiguration(A192GCMKW, listOf(A192CBC_HS384, A192GCM)),
        SymmetricConfiguration(A256GCMKW, listOf(A256CBC_HS512, A256GCM)),
    )

    symmetricConfiguration.forEach { config ->
        runBlocking {
            val ephemeralKey = (config.algorithm as JweAlgorithm.Symmetric).algorithm.randomKey()
            require(ephemeralKey is SymmetricKey.Integrated)

            val jvmEncrypter = AESEncrypter(ephemeralKey.secretKey.getOrThrow())
            val jvmDecrypter = AESDecrypter(ephemeralKey.secretKey.getOrThrow())

            val encrypter = EncryptJweSymmetric(ephemeralKey)
            val decrypter = DecryptJweSymmetric(ephemeralKey)
            val randomPayload = uuid4().toString()

            config.encryption.forEach { encryptionMethod ->
                "${config.algorithm.identifier}, ${encryptionMethod}" - {
                    "Encrypted object from ext. library can be decrypted with int. library" {
                        val libJweHeader =
                            JWEHeader.Builder(JWEAlgorithm(config.algorithm.identifier), encryptionMethod.joseAlgorithm)
                                .type(JOSEObjectType("something"))
                                .build()
                        val libJweObject = JWEObject(libJweHeader, Payload(randomPayload))
                            .apply { encrypt(jvmEncrypter) }
                        val encryptedJwe = libJweObject.serialize()

                        val parsedJwe = JweEncrypted.deserialize(encryptedJwe).getOrThrow()
                        val result = decrypter(parsedJwe).getOrThrow()
                        result.payload shouldBe randomPayload
                    }

                    "Encrypted object from int. library can be decrypted with ext. library" {
                        val encrypted = encrypter(
                            JweHeader(
                                algorithm = config.algorithm,
                                encryption = encryptionMethod,
                            ),
                            randomPayload,
                        ).getOrThrow().serialize()

                        val parsed = JWEObject.parse(encrypted).shouldNotBeNull()

                        parsed.decrypt(jvmDecrypter)
                        parsed.payload.toBytes().decodeToString() shouldBe randomPayload
                    }
                }
            }
        }
    }
}
private data class SymmetricConfiguration(
    val algorithm: JweAlgorithm,
    val encryption: Collection<JweEncryption>,
)

private data class EcdhesConfiguration(
    val curve: ECCurve,
    val encryption: Collection<JweEncryption>,
)

private val JweEncryption.joseAlgorithm: EncryptionMethod
    get() = when (this) {
        A128GCM -> EncryptionMethod.A128GCM
        A192GCM -> EncryptionMethod.A192GCM
        A256GCM -> EncryptionMethod.A256GCM
        A128CBC_HS256 -> EncryptionMethod.A128CBC_HS256
        A192CBC_HS384 -> EncryptionMethod.A192CBC_HS384
        A256CBC_HS512 -> EncryptionMethod.A256CBC_HS512
    }
