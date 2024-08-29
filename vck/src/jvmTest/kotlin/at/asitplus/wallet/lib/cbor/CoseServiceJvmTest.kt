package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.cosef.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.DefaultKeyPairAdapter
import at.asitplus.wallet.lib.agent.EphemeralKeyPariAdapter
import at.asitplus.wallet.lib.agent.PlatformCryptoShim
import com.authlete.cbor.CBORByteArray
import com.authlete.cbor.CBORDecoder
import com.authlete.cbor.CBORTaggedItem
import com.authlete.cose.*
import com.authlete.cose.constants.COSEAlgorithms
import com.benasher44.uuid.uuid4
import io.kotest.assertions.withClue
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

class CoseServiceJvmTest : FreeSpec({

    val configurations: List<Pair<String, Int>> =
        listOf(
            ("EC" to 256),
            ("EC" to 384),
            ("EC" to 521),
        )

    configurations.forEach { thisConfiguration ->
        repeat(2) { number ->
            val sigAlgo = when (thisConfiguration.first) {
                "EC" -> when (thisConfiguration.second) {
                    256 -> X509SignatureAlgorithm.ES256
                    384 -> X509SignatureAlgorithm.ES384
                    521 -> X509SignatureAlgorithm.ES512
                    else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                }

                else -> throw IllegalArgumentException("Unknown Key Type") // -||-
            }
            val ephemeralKey = EphemeralKey {
                ec {
                    curve = when (thisConfiguration.second) {
                        256 -> ECCurve.SECP_256_R_1
                        384 -> ECCurve.SECP_384_R_1
                        521 -> ECCurve.SECP_521_R_1
                        else -> throw IllegalArgumentException("Unknown EC Curve size") // necessary(compiler), but otherwise redundant else-branch
                    }
                    digests = setOf(curve.nativeDigest)
                }
            }.getOrThrow()


            val coseAlgorithm = sigAlgo.toCoseAlgorithm().getOrThrow()
            val extLibAlgorithm = when (sigAlgo) {
                X509SignatureAlgorithm.ES256 -> COSEAlgorithms.ES256
                X509SignatureAlgorithm.ES384 -> COSEAlgorithms.ES384
                X509SignatureAlgorithm.ES512 -> COSEAlgorithms.ES512
                else -> throw IllegalArgumentException("Unknown JweAlgorithm")
            }

            val extLibVerifier = COSEVerifier(ephemeralKey.publicKey.getJcaPublicKey().getOrThrow() as ECPublicKey)

            @OptIn(HazardousMaterials::class)
            val extLibSigner = COSESigner(ephemeralKey.jcaPrivateKey as ECPrivateKey)


            val keyPairAdapter = EphemeralKeyPariAdapter(ephemeralKey)
            val cryptoService = DefaultCryptoService(keyPairAdapter)
            val coseService = DefaultCoseService(cryptoService)
            val verifierCoseService = DefaultVerifierCoseService()
            val coseKey = ephemeralKey.publicKey.toCoseKey().getOrThrow()

            val randomPayload = uuid4().toString()

            val testIdentifier = "$sigAlgo, ${thisConfiguration.second}, ${number + 1}"

            "$testIdentifier:" - {

                "Signed object from int. library can be verified with int. library" {
                    val signed = coseService.createSignedCose(
                        payload = randomPayload.encodeToByteArray(),
                    ).getOrThrow()

                    withClue("$sigAlgo: Signature: ${signed.signature.encodeToTlv().toDerHexString()}") {
                        verifierCoseService.verifyCose(signed, cryptoService.keyPairAdapter.coseKey)
                            .isSuccess shouldBe true
                    }
                }

                "Signed object from ext. library can be verified with int. library" {
                    val extLibProtectedHeader = COSEProtectedHeaderBuilder().alg(extLibAlgorithm).build()
                    val extLibSigStructure = SigStructureBuilder().signature1()
                        .bodyAttributes(extLibProtectedHeader)
                        .payload(randomPayload)
                        .build()
                    val extLibSignature = extLibSigner.sign(extLibSigStructure, extLibAlgorithm)
                    val extLibCoseSign1 = COSESign1Builder()
                        .protectedHeader(extLibProtectedHeader)
                        .payload(randomPayload)
                        .signature(extLibSignature)
                        .build()
                    extLibVerifier.verify(extLibCoseSign1) shouldBe true

                    // Parsing to our structure verifying payload
                    val coseSigned = CoseSigned.deserialize(extLibCoseSign1.encode()).getOrThrow()
                    coseSigned.payload shouldBe randomPayload.encodeToByteArray()
                    val parsedDefLengthSignature = coseSigned.signature as CryptoSignature.EC.DefiniteLength
                    val parsedSig = parsedDefLengthSignature.rawByteArray.encodeToString(Base16())
                    val extLibSig = extLibSignature.encodeToString(Base16())

                    withClue(
                        "$sigAlgo: \nSignatures should match\nOurs:\n$parsedSig\nTheirs:\n$extLibSig"
                    ) {
                        parsedSig shouldBe extLibSig
                    }

                    val signed = coseService.createSignedCose(
                        protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                        payload = randomPayload.encodeToByteArray(),
                        addCertificate = false,
                        addKeyId = false,
                    ).getOrThrow()
                    val signedSerialized = signed.serialize().encodeToString(Base16())
                    val extLibSerialized = extLibCoseSign1.encode().encodeToString(Base16())
                    signedSerialized.length shouldBe extLibSerialized.length

                    withClue("$sigAlgo: Signature: ${parsedSig}") {
                        verifierCoseService.verifyCose(coseSigned, coseKey).isSuccess shouldBe true
                    }
                }

                "Signed object from int. library can be verified with ext. library" {
                    val coseSigned = coseService.createSignedCose(
                        protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                        payload = randomPayload.encodeToByteArray(),
                        addCertificate = false,
                        addKeyId = false,
                    ).getOrThrow()

                    val parsed = CBORDecoder(byteArrayOf(0xD2.toByte()) + coseSigned.serialize()).next()
                        .shouldBeInstanceOf<CBORTaggedItem>()
                    val parsedCoseSign1 = parsed.tagContent
                        .shouldBeInstanceOf<COSESign1>()
                    val parsedPayload = parsedCoseSign1.payload
                        .shouldBeInstanceOf<CBORByteArray>()

                    parsedPayload.value shouldBe randomPayload.encodeToByteArray()
                    val parsedSignature = parsedCoseSign1.signature.value.encodeToString(Base16())
                    val parsedDefLengthSignature = coseSigned.signature as CryptoSignature.EC.DefiniteLength
                    val signature = parsedDefLengthSignature.rawByteArray.encodeToString(Base16())
                    parsedSignature shouldBe signature

                    val extLibSigInput =
                        SigStructureBuilder().sign1(parsedCoseSign1).build().encode().encodeToString(Base16())
                    val signatureInput = CoseSignatureInput(
                        contextString = "Signature1",
                        protectedHeader = ByteStringWrapper(CoseHeader(algorithm = coseAlgorithm)),
                        externalAad = byteArrayOf(),
                        payload = randomPayload.encodeToByteArray(),
                    ).serialize().encodeToString(Base16())

                    withClue("$sigAlgo: Our input:\n$signatureInput\n Their input:\n$extLibSigInput") {
                        extLibSigInput shouldBe signatureInput
                    }

                    withClue("$sigAlgo: Signature: $parsedSignature") {
                        extLibVerifier.verify(parsedCoseSign1) shouldBe true
                    }
                }
            }
        }
    }
})