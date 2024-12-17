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
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.NothingSerializer
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

    // "T" translates to 54 hex = "bytes(20)" in CBOR meaning,
    // so we'll test if our implementation really uses the plain bytes,
    // and does not truncate it after reading 20 bytes during deserialization
    "signed object with pseudo-random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val payloadToUse = "This is the content: ".encodeToByteArray() + randomPayload
        val signed = coseService.createSignedCose(
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = payloadToUse,
            serializer = parameterSerializer,
        ).getOrThrow()

        signed.payload shouldBe payloadToUse
        signed.wireFormat.payload shouldBe payloadToUse
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        verifierCoseService.verifyCose(parsed, coseKey).isSuccess shouldBe true
    }

    "signed object with random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = coseService.createSignedCose(
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = randomPayload,
            serializer = parameterSerializer,
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        verifierCoseService.verifyCose(parsed, coseKey).isSuccess shouldBe true
    }

    "signed object with MSO payload can be verified" {
        val parameterSerializer = MobileSecurityObject.serializer()
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
            serializer = parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe mso
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer)).getOrThrow()
            .shouldBe(signed)

        verifierCoseService.verifyCose(parsed, coseKey).isSuccess shouldBe true
    }

    "signed object without payload can be verified" {
        val parameterSerializer = NothingSerializer()
        val signed = coseService.createSignedCose(
            unprotectedHeader = null,
            payload = null,
            serializer = parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe null
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer)).getOrThrow()
            .shouldBe(signed)

        verifierCoseService.verifyCose(parsed, coseKey).isSuccess shouldBe true
    }

})

