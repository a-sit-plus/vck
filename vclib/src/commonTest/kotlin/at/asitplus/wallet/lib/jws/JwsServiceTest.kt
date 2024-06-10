package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweEncrypted
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.jsonSerializer
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToString
import kotlin.random.Random

class JwsServiceTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var jwsService: JwsService
    lateinit var verifierJwsService: VerifierJwsService
    lateinit var randomPayload: String

    beforeEach {
        cryptoService = DefaultCryptoService()
        jwsService = DefaultJwsService(cryptoService)
        verifierJwsService = DefaultVerifierJwsService()
        randomPayload = uuid4().toString()
    }

    "signed object with bytes can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, payload).getOrThrow()
        signed.shouldNotBeNull()
        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "Object can be reconstructed" {
        val payload = randomPayload.encodeToByteArray()
        val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, payload).getOrThrow().serialize()
        signed.shouldNotBeNull()

        val parsed = JwsSigned.parse(signed).getOrThrow()
        parsed.serialize() shouldBe signed
        parsed.payload shouldBe payload

        val result = verifierJwsService.verifyJwsObject(parsed)
        result shouldBe true
    }

    "signed object can be verified" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val signed =
            jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray()).getOrThrow()
        signed.shouldNotBeNull()
        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with automatically added params can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed = jwsService.createSignedJwsAddingParams(payload = payload, addX5c = false).getOrThrow()
        signed.shouldNotBeNull()
        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with jsonWebKey can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = cryptoService.keyPairAdapter.jsonWebKey)
        val signed = jwsService.createSignedJws(header, payload).getOrThrow()
        signed.shouldNotBeNull()
        val result = verifierJwsService.verifyJwsObject(signed)
        result shouldBe true
    }

    "signed object with kid from jku can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val kid = Random.nextBytes(16).encodeToString(Base64())
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, keyId = kid, jsonWebKeySetUrl = jku)
        val signed = jwsService.createSignedJws(header, payload).getOrThrow()
        val validKey = cryptoService.keyPairAdapter.jsonWebKey.copy(keyId = kid)
        val jwkSetRetriever: JwkSetRetrieverFunction = { JsonWebKeySet(keys = listOf(validKey)) }
        verifierJwsService = DefaultVerifierJwsService(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService.verifyJwsObject(signed) shouldBe true
    }

    "signed object with kid from jku, returning invalid key, can not be verified" {
        val payload = randomPayload.encodeToByteArray()
        val kid = Random.nextBytes(16).encodeToString(Base64())
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, keyId = kid, jsonWebKeySetUrl = jku)
        val signed = jwsService.createSignedJws(header, payload).getOrThrow()
        val invalidKey = DefaultCryptoService().keyPairAdapter.jsonWebKey
        val jwkSetRetriever: JwkSetRetrieverFunction = { JsonWebKeySet(keys = listOf(invalidKey)) }
        verifierJwsService = DefaultVerifierJwsService(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService.verifyJwsObject(signed) shouldBe false
    }

    "encrypted object can be decrypted" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val encrypted = jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            stringPayload.encodeToByteArray(),
            cryptoService.keyPairAdapter.jsonWebKey,
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        ).getOrThrow().serialize()
        encrypted.shouldNotBeNull()
        val parsed = JweEncrypted.parse(encrypted).getOrThrow()

        val result = jwsService.decryptJweObject(parsed, encrypted).getOrThrow()
        result.payload.decodeToString() shouldBe stringPayload
    }
})
