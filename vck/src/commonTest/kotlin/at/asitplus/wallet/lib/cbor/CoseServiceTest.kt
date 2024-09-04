package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

class CoseServiceTest : FreeSpec({

    lateinit var cryptoService: CryptoService
    lateinit var coseService: CoseService
    lateinit var verifierCoseService: VerifierCoseService
    lateinit var randomPayload: ByteArray

    beforeEach {
        val keyPairAdapter = EphemeralKeyWithSelfSignedCert()
        cryptoService = DefaultCryptoService(keyPairAdapter)
        coseService = DefaultCoseService(cryptoService)
        verifierCoseService = DefaultVerifierCoseService()
        randomPayload = Random.nextBytes(32)
    }

    "signed object with bytes can be verified" {
        val signed = coseService.createSignedCose(
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = randomPayload,
            addKeyId = true
        ).getOrThrow()
        signed.shouldNotBeNull()
        println(signed.serialize().encodeToString(Base16(strict = true)))

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize()).getOrThrow()

        cryptoService.keyWithCert.publicKey.toCoseKey().getOrNull() shouldNotBe null
        val result = verifierCoseService.verifyCose(parsed, cryptoService.keyWithCert.publicKey.toCoseKey().getOrThrow())
        result.isSuccess shouldBe true
    }

    "signed object without payload can be verified" {
        val signed = coseService.createSignedCose(
            unprotectedHeader = null,
            payload = null,
            addKeyId = true
        ).getOrThrow()
        signed.shouldNotBeNull()
        println(signed.serialize().encodeToString(Base16(strict = true)))

        signed.payload shouldBe null
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(signed.serialize()).getOrThrow()

        cryptoService.keyWithCert.publicKey.toCoseKey().getOrNull() shouldNotBe null
        val result = verifierCoseService.verifyCose(parsed, cryptoService.keyWithCert.publicKey.toCoseKey().getOrThrow())
        result.isSuccess shouldBe true
    }

})
