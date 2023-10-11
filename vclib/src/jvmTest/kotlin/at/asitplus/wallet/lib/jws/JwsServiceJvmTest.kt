package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.jsonSerializer
import com.benasher44.uuid.uuid4
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

class JwsServiceJvmTest : FreeSpec({

    lateinit var keyPair: KeyPair
    lateinit var cryptoService: CryptoService
    lateinit var jwsService: JwsService
    lateinit var verifierJwsService: VerifierJwsService
    lateinit var randomPayload: String

    beforeTest {
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        cryptoService = DefaultCryptoService(keyPair)
        jwsService = DefaultJwsService(cryptoService)
        verifierJwsService = DefaultVerifierJwsService()
        randomPayload = uuid4().toString()
    }

    "signed object from ext. library can be verified" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val libHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("JWT"))
            .keyID(cryptoService.toPublicKey().toJsonWebKey().keyId!!)
            .build()
        val libObject = JWSObject(libHeader, Payload(stringPayload)).also {
            it.sign(ECDSASigner(keyPair.private as ECPrivateKey))
        }
        val signed = libObject.serialize()

        val parsed = JwsSigned.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload.decodeToString() shouldBe stringPayload

        val result = verifierJwsService.verifyJwsObject(parsed, signed)
        result shouldBe true
    }

    "signed object can be verified with ext. library" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())

        val parsed = JWSObject.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload.toString() shouldBe stringPayload

        val result = parsed.verify(ECDSAVerifier(keyPair.public as ECPublicKey))
        result shouldBe true
    }

    "encrypted object from ext. library can be decrypted" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val libHeader = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A256GCM)
            .type(JOSEObjectType(JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON))
            .contentType(JwsContentTypeConstants.DIDCOMM_PLAIN_JSON)
            .keyID(cryptoService.toPublicKey().toJsonWebKey().keyId!!)
            .build()
        val libObject = JWEObject(libHeader, Payload(stringPayload)).also {
            it.encrypt(ECDHEncrypter(keyPair.public as ECPublicKey))
        }
        val encrypted = libObject.serialize()

        val parsed = JweEncrypted.parse(encrypted)
        parsed.shouldNotBeNull()

        val result = jwsService.decryptJweObject(parsed, encrypted)
        result?.payload?.decodeToString() shouldBe stringPayload
    }

    "encrypted object can be decrypted with ext. library" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val encrypted = jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            stringPayload.encodeToByteArray(),
            cryptoService.toPublicKey().toJsonWebKey(),
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        )

        val parsed = JWEObject.parse(encrypted)
        parsed.shouldNotBeNull()
        parsed.payload.shouldBeNull()

        parsed.decrypt(ECDHDecrypter(keyPair.private as ECPrivateKey))
        parsed.payload.toString() shouldBe stringPayload
    }

})
