package at.asitplus.wallet.lib.cbor

import at.asitplus.iso.DeviceKeyInfo
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValidityInfo
import at.asitplus.iso.ValueDigest
import at.asitplus.iso.ValueDigestList
import at.asitplus.signum.indispensable.HMAC
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyOperation
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.CoseMac
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.ktor.util.hex
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.NothingSerializer
import kotlin.random.Random
import kotlin.time.Clock

@OptIn(ExperimentalSerializationApi::class)
class CoseServiceTest : FreeSpec({

    lateinit var signCose: SignCoseFun<ByteArray>
    lateinit var signCoseNothing: SignCoseFun<Nothing>
    lateinit var signCoseMso: SignCoseFun<MobileSecurityObject>
    lateinit var signCoseDetached: SignCoseDetachedFun<ByteArray>
    lateinit var randomPayload: ByteArray
    lateinit var signCoseKey: CoseKey

    lateinit var macCose: MacCoseFun<ByteArray>
    lateinit var macCoseMso: MacCoseFun<MobileSecurityObject>
    lateinit var macCoseNothing: MacCoseFun<Nothing>
    lateinit var macCoseDetached: MacCoseDetachedFun<ByteArray>
    lateinit var macCoseKey: CoseKey

    beforeEach {
        val signKeyMaterial = EphemeralKeyWithoutCert()
        signCose = SignCose(signKeyMaterial)
        signCoseNothing = SignCose(signKeyMaterial)
        signCoseMso = SignCose(signKeyMaterial)
        signCoseDetached = SignCoseDetached(signKeyMaterial)
        randomPayload = Random.nextBytes(32)
        signCoseKey = signKeyMaterial.publicKey.toCoseKey().getOrThrow()

        val macAlgorithm = HMAC.SHA256
        val rawKey = Random.nextBytes(32)
        macCoseKey = CoseKey.forMacKey(macAlgorithm, rawKey, null, CoseKeyOperation.MAC_CREATE, CoseKeyOperation.MAC_VERIFY)
        macCose = MacCose(macCoseKey)
        macCoseMso = MacCose(macCoseKey)
        macCoseNothing = MacCose(macCoseKey)
        macCoseDetached = MacCoseDetached(macCoseKey)
    }

    // "T" translates to 54 hex = "bytes(20)" in CBOR meaning,
    // so we'll test if our implementation really uses the plain bytes,
    // and does not truncate it after reading 20 bytes during deserialization
    "signed object with pseudo-random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val payloadToUse = "This is the content: ".encodeToByteArray() + randomPayload
        val signed = signCose(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
            unprotectedHeader = null,
            payload = payloadToUse,
            serializer = parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe payloadToUse
        signed.wireFormat.payload shouldBe payloadToUse
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<ByteArray>()(parsed, signCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "mac object with pseudo-random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val payloadToUse = "This is the content: ".encodeToByteArray() + randomPayload
        val maced = macCose(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = payloadToUse,
            serializer = parameterSerializer
        ).getOrThrow()

        maced.payload shouldBe payloadToUse
        maced.wireFormat.payload shouldBe payloadToUse
        maced.tag.shouldNotBeNull()

        val serialized = maced.serialize(parameterSerializer)

        val parsed = CoseMac.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(maced)

        VerifyCoseMacWithKey<ByteArray>()(parsed, macCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = signCose(
            protectedHeader = null,
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
            payload = randomPayload,
            serializer = parameterSerializer,
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val serialized = signed.serialize(parameterSerializer)

        val parsed = CoseSigned.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<ByteArray>()(parsed, signCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "maced object with random bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val maced = macCose(
            protectedHeader = null,
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            payload = randomPayload,
            serializer = parameterSerializer,
        ).getOrThrow()

        maced.payload shouldBe randomPayload
        maced.tag.shouldNotBeNull()

        val serialized = maced.serialize(parameterSerializer)

        val parsed = CoseMac.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(maced)

        VerifyCoseMacWithKey<ByteArray>()(parsed, macCoseKey, byteArrayOf(), null).isSuccess shouldBe true
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
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256),
            unprotectedHeader = null,
            payload = mso,
            serializer = parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe mso
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer)).getOrThrow()
            .shouldBe(signed)

        VerifyCoseSignatureWithKey<MobileSecurityObject>()(parsed, signCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "maced object with MSO payload can be verified" {
        val parameterSerializer = MobileSecurityObject.serializer()
        val mso = MobileSecurityObject(
            version = "1.0",
            digestAlgorithm = "SHA-256",
            valueDigests = mapOf(
                "foo" to ValueDigestList(listOf(ValueDigest(0U, byteArrayOf())))
            ),
            deviceKeyInfo = DeviceKeyInfo(
                macCoseKey
            ),
            docType = "docType",
            validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now())
        )
        val maced = macCoseMso(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256),
            unprotectedHeader = null,
            payload = mso,
            serializer = parameterSerializer
        ).getOrThrow()

        maced.payload shouldBe mso
        maced.tag.shouldNotBeNull()

        val parsed = CoseMac.deserialize(parameterSerializer, maced.serialize(parameterSerializer)).getOrThrow()
            .shouldBe(maced)

        VerifyCoseMacWithKey<MobileSecurityObject>()(parsed, macCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with null payload can be verified" {
        val parameterSerializer = NothingSerializer()
        val signed = signCoseNothing(null, null, null, parameterSerializer).getOrThrow()

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

        VerifyCoseSignatureWithKey<Nothing>()(parsed, signCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "maced object with null payload can be verified" {
        val parameterSerializer = NothingSerializer()
        val maced = macCoseNothing(null, null, null, parameterSerializer).getOrThrow()

        maced.payload shouldBe null
        maced.tag.shouldNotBeNull()
        val serialized = maced.serialize(parameterSerializer).apply {
            // A0 = empty map (unprotected header)
            // F6 = CBOR Null (payload)
            // 58 20 = 32 bytes (hmac256)
            encodeToString(Base16()) shouldContain "A0F65820"
        }

        val parsed = CoseMac.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(maced)

        VerifyCoseMacWithKey<Nothing>()(parsed, macCoseKey, byteArrayOf(), null).isSuccess shouldBe true
    }

    "signed object with random bytes, transported detached, can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = signCoseDetached(
            protectedHeader = null,
            unprotectedHeader = null,
            payload = randomPayload,
            serializer = parameterSerializer
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

        with(VerifyCoseSignatureWithKey<ByteArray>()) {
            invoke(parsed, signCoseKey, byteArrayOf(), randomPayload).isSuccess shouldBe true
            invoke(parsed, signCoseKey, byteArrayOf(), randomPayload + byteArrayOf(0)).isSuccess shouldBe false
            invoke(parsed, signCoseKey, byteArrayOf(), null).isSuccess shouldBe false
        }
    }

    "maced object with random bytes, transported detached, can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val maced = macCoseDetached(
            protectedHeader = null,
            unprotectedHeader = null,
            payload = randomPayload,
            serializer = parameterSerializer
        ).getOrThrow()

        maced.payload shouldBe null
        maced.tag.shouldNotBeNull()

        val serialized = maced.serialize(parameterSerializer).apply {
            // A0 = empty map (unprotected header)
            // F6 = CBOR Null (payload)
            // 58 20 = 32 bytes (HMAC256)
            encodeToString(Base16()) shouldContain "A0F65820"
        }

        val parsed = CoseMac.deserialize(parameterSerializer, serialized).getOrThrow()
            .shouldBe(maced)

        with(VerifyCoseMacWithKey<ByteArray>()) {
            invoke(parsed, macCoseKey, byteArrayOf(), randomPayload).isSuccess shouldBe true
            invoke(parsed, macCoseKey, byteArrayOf(), randomPayload + byteArrayOf(0)).isSuccess shouldBe false
            invoke(parsed, macCoseKey, byteArrayOf(), null).isSuccess shouldBe false
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

    // https://github.com/cose-wg/Examples/tree/master/mac0-tests
    "MAC0 sample 01 can be verified" {
        val input = """
            D18441A0A1010554546869732069732074686520636F6E74656E742E5820176DCE14C1E57430C13658233F41DC89AA4FA0FF9B8783F23B0EF51CA6B026BC
        """.trimIndent()

        val maced = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        maced.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        maced.prepareCoseMacInput()
            .encodeToString(Base16Strict) shouldBe "84644D414330404054546869732069732074686520636F6E74656E742E"
    }

    // https://github.com/cose-wg/Examples/tree/master/mac0-tests
    "MAC0 sample 02 can be verified" {
        val input = """
            D18440A1010554546869732069732074686520636F6E74656E742E58200FECAEC59BB46CC8A488AACA4B205E322DD52696B75A45768D3C302DD4BAE2F7
        """.trimIndent()

        val maced = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        maced.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        maced.prepareCoseMacInput(hex("ff00ee11dd22cc33bb44aa559966"))
            .encodeToString(Base16Strict) shouldBe "84644D414330404EFF00EE11DD22CC33BB44AA55996654546869732069732074686520636F6E74656E742E"
    }

    // https://github.com/cose-wg/Examples/tree/master/mac0-tests
    "MAC0 sample 03 can be verified" {
        val input = """
            8440A1010554546869732069732074686520636F6E74656E742E5820176DCE14C1E57430C13658233F41DC89AA4FA0FF9B8783F23B0EF51CA6B026BC
        """.trimIndent()

        val maced = CoseMac.deserialize(ByteArraySerializer(), input.decodeToByteArray(Base16())).getOrThrow()

        maced.payload shouldBe "546869732069732074686520636F6E74656E742E".decodeToByteArray(Base16())
        maced.prepareCoseMacInput()
            .encodeToString(Base16Strict) shouldBe "84644D414330404054546869732069732074686520636F6E74656E742E"
    }
})

