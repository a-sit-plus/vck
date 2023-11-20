package at.asitplus.wallet.lib.jws

import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.jsonSerializer
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToString

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
        val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, payload)
        signed.shouldNotBeNull()

        val parsed = JwsSigned.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload shouldBe payload

        val result = verifierJwsService.verifyJwsObject(parsed, signed)
        result shouldBe true
    }

    "signed object can be verified" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val signed = jwsService.createSignedJwt(JwsContentTypeConstants.JWT, stringPayload.encodeToByteArray())
        signed.shouldNotBeNull()

        val parsed = JwsSigned.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload.decodeToString() shouldBe stringPayload

        val result = verifierJwsService.verifyJwsObject(parsed, signed)
        result shouldBe true
    }

    "signed object with automatically added params can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed = jwsService.createSignedJwsAddingParams(JwsHeader(JwsAlgorithm.ES256), payload)
        signed.shouldNotBeNull()

        val parsed = JwsSigned.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload shouldBe payload

        val result = verifierJwsService.verifyJwsObject(parsed, signed)
        result shouldBe true
    }

    "signed object with jsonWebKey can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val header = JwsHeader(JwsAlgorithm.ES256, jsonWebKey = cryptoService.jsonWebKey)
        val signed = jwsService.createSignedJws(header, payload)
        signed.shouldNotBeNull()

        val parsed = JwsSigned.parse(signed)
        parsed.shouldNotBeNull()
        parsed.payload shouldBe payload

        val result = verifierJwsService.verifyJwsObject(parsed, signed)
        result shouldBe true
    }

    "encrypted object can be decrypted" {
        val stringPayload = jsonSerializer.encodeToString(randomPayload)
        val encrypted = jwsService.encryptJweObject(
            JwsContentTypeConstants.DIDCOMM_ENCRYPTED_JSON,
            stringPayload.encodeToByteArray(),
            cryptoService.jsonWebKey,
            JwsContentTypeConstants.DIDCOMM_PLAIN_JSON,
            JweAlgorithm.ECDH_ES,
            JweEncryption.A256GCM,
        )
        encrypted.shouldNotBeNull()
        val parsed = JweEncrypted.parse(encrypted)
        parsed.shouldNotBeNull()

        val result = jwsService.decryptJweObject(parsed, encrypted)
        result?.payload?.decodeToString() shouldBe stringPayload
    }

})
