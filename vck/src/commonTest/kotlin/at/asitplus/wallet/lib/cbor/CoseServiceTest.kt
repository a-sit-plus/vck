package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.iso.*
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.NothingSerializer
import kotlin.random.Random

@OptIn(ExperimentalSerializationApi::class)
class CoseServiceTest : FreeSpec({

    lateinit var signCose: SignCoseFun<ByteArray>
    lateinit var signCoseNothing: SignCoseFun<Nothing>
    lateinit var signCoseMso: SignCoseFun<MobileSecurityObject>
    lateinit var signCoseDetached: SignCoseDetachedFun<ByteArray>
    lateinit var randomPayload: ByteArray
    lateinit var coseKey: CoseKey

    beforeEach {
        val keyMaterial = EphemeralKeyWithoutCert()
        signCose = SignCose(keyMaterial)
        signCoseNothing = SignCose(keyMaterial)
        signCoseMso = SignCose(keyMaterial)
        signCoseDetached = SignCoseDetached(keyMaterial)
        randomPayload = Random.nextBytes(32)
        coseKey = keyMaterial.publicKey.toCoseKey().getOrThrow()
    }

    // "T" translates to 54 hex = "bytes(20)" in CBOR meaning,
    // so we'll test if our implementation really uses the plain bytes,
    // and does not truncate it after reading 20 bytes during deserialization
    "signed object with pseudo-random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val payloadToUse = "This is the content: ".encodeToByteArray() + randomPayload
        val signed = signCose(
            CoseHeader(algorithm = CoseAlgorithm.ES256),
            null,
            payloadToUse,
            parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe payloadToUse
        signed.wireFormat.payload shouldBe payloadToUse
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<ByteArray>()(parsed, coseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = signCose(
            null,
            CoseHeader(algorithm = CoseAlgorithm.ES256),
            randomPayload,
            parameterSerializer,
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<ByteArray>()(parsed, coseKey, byteArrayOf(), null).isSuccess shouldBe true
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
        val signed = signCoseMso(
            CoseHeader(algorithm = CoseAlgorithm.ES256),
            null,
            mso,
            parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe mso
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer)).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<MobileSecurityObject>()(parsed, coseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with null payload can be verified" {
        val parameterSerializer = NothingSerializer()
        val signed = signCoseNothing(
            null,
            null,
            null,
            parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe null
        signed.signature.shouldNotBeNull()
        val serialized = signed.serialize(parameterSerializer).apply {
            // A0 = empty map (unprotected header)
            // F6 = CBOR Null (payload)
            // 58 40 = 64 bytes (signature)
            encodeToString(Base16()) shouldContain "A0F65840"
        }

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<Nothing>()(parsed, coseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with random bytes, transported detached, can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = signCoseDetached(null, null, randomPayload, parameterSerializer).getOrThrow()

        signed.payload shouldBe null
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer).apply {
            // A0 = empty map (unprotected header)
            // F6 = CBOR Null (payload)
            // 58 40 = 64 bytes (signature)
            encodeToString(Base16()) shouldContain "A0F65840"
        }

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        with(VerifyCoseSignatureWithKey<ByteArray>()) {
            invoke(parsed, coseKey, byteArrayOf(), randomPayload).isSuccess shouldBe true
            invoke(parsed, coseKey, byteArrayOf(), randomPayload + byteArrayOf(0)).isSuccess shouldBe false
            invoke(parsed, coseKey, byteArrayOf(), null).isSuccess shouldBe false
        }
    }

    // https://github.com/cose-wg/Examples/tree/master/sign1-tests
    "sample 01 can be verified" {
        val input = """
            D28441A0A201260442313154546869732069732074686520636F6E74656E742E584087DB0D2E5571843B78AC33ECB2830DF7B6E0A4D5
            B7376DE336B23C591C90C425317E56127FBE04370097CE347087B233BF722B64072BEB4486BDA4031D27244F
        """.trimIndent()

        val signed = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        signed.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        signed.prepareCoseSignatureInput()
            .encodeToString(Base16Strict) shouldBe "846A5369676E617475726531404054546869732069732074686520636F6E74656E742E"
    }

    // https://github.com/cose-wg/Examples/tree/master/sign1-tests
    "sample 02 can be verified" {
        val input = """
            D28443A10126A10442313154546869732069732074686520636F6E74656E742E584010729CD711CB3813D8D8E944A8DA7111E7B258C9
            BDCA6135F7AE1ADBEE9509891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B
        """.trimIndent()

        val signed = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        signed.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        signed.prepareCoseSignatureInput(externalAad = "11aa22bb33cc44dd55006699".decodeToByteArray(Base16()))
            .encodeToString(Base16Strict) shouldBe "846A5369676E61747572653143A101264C11AA22BB33CC44DD5500669954546869732069732074686520636F6E74656E742E"
    }

    // https://github.com/cose-wg/Examples/tree/master/sign1-tests
    "sample 03 can be verified" {
        val input = """
            8443A10126A10442313154546869732069732074686520636F6E74656E742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C08
            3106C4D25A91AEF0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36
        """.trimIndent()

        val signed = CoseSigned.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        signed.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        signed.prepareCoseSignatureInput() shouldBe "846A5369676E61747572653143A101264054546869732069732074686520636F6E74656E742E".decodeToByteArray(
            Base16()
        )
    }
})

