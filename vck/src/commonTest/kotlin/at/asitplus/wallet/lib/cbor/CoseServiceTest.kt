package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.iso.*
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.datetime.Clock
import kotlin.random.Random

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

    "signed object with MSO payload can be verified" {
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                "foo" to ValueDigestList(listOf(ValueDigest(0U, byteArrayOf())))
            ),
            deviceKeyInfo = DeviceKeyInfo(
                CoseKey(
                    CoseKeyType.EC2,
                    keyParams = CoseKeyParams.EcYBoolParams(CoseEllipticCurve.P256)
                )
            ),
            docType = "docType",
            validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now())
        )
        val signed = coseService.createSignedCose(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = mso,
        ).getOrThrow()

        signed.getTypedPayload(MobileSecurityObject.serializer()).getOrThrow().shouldNotBeNull().value shouldBe mso
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

