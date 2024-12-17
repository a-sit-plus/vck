package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.iso.*
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
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
        // Prevent COSE-special bytes at the start of the payload
        randomPayload = "This is the content: ".encodeToByteArray() + Random.nextBytes(32)
        coseKey = keyMaterial.publicKey.toCoseKey().getOrThrow()
    }

    "signed object with bytes can be verified" {
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
        withClue(
            "signed.payload ${signed.wireFormat.payload?.encodeToString(Base16())} " +
                    "vs parsed.payload: ${parsed.payload?.encodeToString(Base16())}"
        ) {
            parsed shouldBe signed
        }

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
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
        parsed shouldBe signed

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
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
        parsed shouldBe signed

        val result = verifierCoseService.verifyCose(parsed, coseKey)
        result.isSuccess shouldBe true
    }

})

