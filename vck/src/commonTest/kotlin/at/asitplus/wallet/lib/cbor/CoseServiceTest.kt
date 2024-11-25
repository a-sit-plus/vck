package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlin.random.Random

@OptIn(ExperimentalSerializationApi::class)
class CoseServiceTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var coseService: CoseService
    lateinit var verifierCoseService: VerifierCoseService
    lateinit var randomPayload: ByteArray
    lateinit var coseKey: CoseKey

    beforeEach {
        val keyMaterial = EphemeralKeyWithoutCert()
        cryptoService = DefaultCryptoService(keyMaterial)
        coseService = DefaultCoseService(cryptoService)
        verifierCoseService = DefaultVerifierCoseService()
        randomPayload = Random.nextBytes(32)
        coseKey = keyMaterial.publicKey.toCoseKey().getOrThrow()
    }

    "signed object with bytes can be verified" {
        val signed = coseService.createSignedCose(
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = randomPayload,
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize()).getOrThrow()

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
    }

    "signed object with custom payload type can be verified" {
        val randomPayload = StringContent(Random.nextBytes(32).encodeToString(Base64()))
        val signed = coseService.createSignedCose(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = ByteStringWrapper(randomPayload),
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize()).getOrThrow()

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
    }

    "signed object without payload can be verified" {
        val signed = coseService.createSignedCose(
            unprotectedHeader = null,
            payload = null,
        ).getOrThrow()

        signed.payload shouldBe null
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize()).getOrThrow()

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
    }

})

@Serializable
data class StringContent(val content: String)
