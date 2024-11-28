package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlin.random.Random

class JwsServiceTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var jwsService: JwsService
    lateinit var verifierJwsService: VerifierJwsService
    lateinit var randomPayload: String

    beforeEach {
        val keyPairAdapter = EphemeralKeyWithoutCert()
        cryptoService = DefaultCryptoService(keyPairAdapter)
        jwsService = DefaultJwsService(cryptoService)
        verifierJwsService = DefaultVerifierJwsService()
        randomPayload = uuid4().toString()
    }

    "signed object with bytes can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed =
            jwsService.createSignedJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()

        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "Object can be reconstructed" {
        val payload = randomPayload.encodeToByteArray()
        val signed =
            jwsService.createSignedJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()
                .serialize()

        val parsed = JwsSigned.deserialize<ByteArray>(ByteArraySerializer(), signed).getOrThrow()
        parsed.serialize() shouldBe signed
        parsed.payload shouldBe payload

        val result = verifierJwsService.verifyJwsObject(parsed)
        result shouldBe true
    }

    "signed object can be verified" {
        val signed =
            jwsService.createSignedJwt(JwsContentTypeConstants.JWT, randomPayload, String.serializer()).getOrThrow()

        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with automatically added params can be verified" {
        val signed = jwsService.createSignedJwsAddingParams(
            payload = randomPayload,
            serializer = String.serializer(),
            addX5c = false
        ).getOrThrow()

        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with jsonWebKey can be verified" {
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = cryptoService.keyMaterial.jsonWebKey)
        val signed = jwsService.createSignedJws(header, randomPayload, String.serializer()).getOrThrow()

        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with kid from jku can be verified" {
        val kid = Random.nextBytes(16).encodeToString(Base64())
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, keyId = kid, jsonWebKeySetUrl = jku)
        val signed = jwsService.createSignedJws(header, randomPayload, String.serializer()).getOrThrow()
        val validKey = cryptoService.keyMaterial.jsonWebKey.copy(keyId = kid)
        val jwkSetRetriever: JwkSetRetrieverFunction = { JsonWebKeySet(keys = listOf(validKey)) }
        verifierJwsService = DefaultVerifierJwsService(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService.verifyJwsObject(signed) shouldBe true
    }

    "signed object with kid from jku, returning invalid key, can not be verified" {
        val kid = Random.nextBytes(16).encodeToString(Base64())
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, keyId = kid, jsonWebKeySetUrl = jku)
        val signed = jwsService.createSignedJws(header, randomPayload, String.serializer()).getOrThrow()
        val invalidKey = EphemeralKeyWithoutCert().jsonWebKey
        val jwkSetRetriever: JwkSetRetrieverFunction = { JsonWebKeySet(keys = listOf(invalidKey)) }
        verifierJwsService = DefaultVerifierJwsService(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService.verifyJwsObject(signed) shouldBe false
    }

    "signed object without public key in header can not be verified" {
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256)
        val signed = jwsService.createSignedJws(header, randomPayload, String.serializer()).getOrThrow()

        verifierJwsService = DefaultVerifierJwsService()
        verifierJwsService.verifyJwsObject(signed) shouldBe false
    }

    "signed object without public key in header, but retrieved out-of-band can be verified" {
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256)
        val signed = jwsService.createSignedJws(header, randomPayload, String.serializer()).getOrThrow()
        val validKey = cryptoService.keyMaterial.jsonWebKey

        val publicKeyLookup: PublicJsonWebKeyLookup = { setOf(validKey) }
        verifierJwsService = DefaultVerifierJwsService(publicKeyLookup = publicKeyLookup)
        verifierJwsService.verifyJwsObject(signed) shouldBe true
    }

    "encrypted object can be decrypted" {
        val encrypted = jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            randomPayload,
            String.serializer(),
            cryptoService.keyMaterial.jsonWebKey,
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        ).getOrThrow().serialize()
        encrypted.shouldNotBeNull()
        val parsed = JweEncrypted.deserialize(encrypted).getOrThrow()

        val result = jwsService.decryptJweObject(parsed, encrypted, String.serializer()).getOrThrow()
        result.payload shouldBe randomPayload
    }
})
