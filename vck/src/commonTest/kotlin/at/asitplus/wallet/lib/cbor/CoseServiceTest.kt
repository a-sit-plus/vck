package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.iso.DeviceKeyInfo
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.iso.ValidityInfo
import at.asitplus.wallet.lib.iso.ValueDigest
import at.asitplus.wallet.lib.iso.ValueDigestList
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

    "signed object with bytes can be verified" {
        val parameterSerializer = ByteArraySerializer()
        val signed = coseService.createSignedCose(
            unprotectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = randomPayload,
            serializer = parameterSerializer,
        ).getOrThrow()

        signed.payload shouldBe randomPayload
        signed.signature.shouldNotBeNull()

        val parsed = CoseSigned.deserialize(
            parameterSerializer,
            signed.serialize(parameterSerializer),
        ).getOrThrow()
        // TODO: this validation fails sometimes, for example in the following case:
        // expected: CoseSigned(protectedHeader=CoseHeader(algorithm=ES256, criticalHeaders=null, contentType=null, kid=6469643A6B65793A7A446E61656F623232706579426469694E65593673545A336D53466E6E4C464B4D68476564366D624467476E6E55627162, iv=null, partialIv=null, coseKey=null, certificateChain=null), unprotectedHeader=CoseHeader(algorithm=ES256, criticalHeaders=null, contentType=null, kid=null, iv=null, partialIv=null, coseKey=null, certificateChain=null), payload=CB5556CC1C3C142642616D9C83EF0D45018AAD9409172B87BA1A36EF68C4946A, signature=1C876F0CF0829F8C59481003A117EFB0D3F7B74C7A9314596C42D440A881DEBA78A47E3DEBA248C47D24D7AFE305001770EA9127A4B15809732B8F1E3FE074E8)
        // actual  : CoseSigned(protectedHeader=CoseHeader(algorithm=ES256, criticalHeaders=null, contentType=null, kid=6469643A6B65793A7A446E61656F623232706579426469694E65593673545A336D53466E6E4C464B4D68476564366D624467476E6E55627162, iv=null, partialIv=null, coseKey=null, certificateChain=null), unprotectedHeader=CoseHeader(algorithm=ES256, criticalHeaders=null, contentType=null, kid=null, iv=null, partialIv=null, coseKey=null, certificateChain=null), payload=56CC1C3C142642616D9C83EF0D45018AAD9409172B, signature=1C876F0CF0829F8C59481003A117EFB0D3F7B74C7A9314596C42D440A881DEBA78A47E3DEBA248C47D24D7AFE305001770EA9127A4B15809732B8F1E3FE074E8)
        parsed shouldBe signed

        val result = verifierCoseService.verifyCose(parsed, coseKey, parameterSerializer)
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
            validityInfo = ValidityInfo(Clock.System.now(), Clock.System.now(), Clock.System.now()),
        )
        val signed = coseService.createSignedCose(
            protectedHeader = CoseHeader(algorithm = CoseAlgorithm.ES256),
            payload = mso,
            serializer = parameterSerializer
        ).getOrThrow()

        signed.payload shouldBe mso
        signed.signature.shouldNotBeNull()

        val parsed =
            CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer))
                .getOrThrow()
        parsed shouldBe signed

        val result = verifierCoseService.verifyCose(parsed, coseKey, parameterSerializer)
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

        val parsed =
            CoseSigned.deserialize(parameterSerializer, signed.serialize(parameterSerializer))
                .getOrThrow()
        parsed shouldBe signed

        val result = verifierCoseService.verifyCose(parsed, coseKey, parameterSerializer)
        result.isSuccess shouldBe true
    }

})

