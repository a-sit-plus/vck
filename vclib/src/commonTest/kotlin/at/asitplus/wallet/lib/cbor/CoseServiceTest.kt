package at.asitplus.wallet.lib.cbor

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlin.random.Random

class CoseServiceTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var coseService: CoseService
    lateinit var verifierCoseService: VerifierCoseService
    lateinit var randomPayload: ByteArray

    beforeEach {
        cryptoService = DefaultCryptoService()
        coseService = DefaultCoseService(cryptoService)
        verifierCoseService = DefaultVerifierCoseService()
        randomPayload = Random.nextBytes(32)
    }

    "signed object with bytes can be verified" {
        val signed =
            coseService.createSignedCose(CoseHeader(algorithm = CoseAlgorithm.ES256), CoseHeader(), randomPayload, true)
                .getOrThrow()
        signed.shouldNotBeNull()
        println(signed.serialize().encodeBase16())

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize())
        parsed.shouldNotBeNull()

        val result = verifierCoseService.verifyCose(parsed, cryptoService.toCoseKey()).getOrThrow()
        result shouldBe true
    }

})
