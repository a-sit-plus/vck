package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseInput
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.testballoon.matrix.*
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import com.authlete.cbor.CBORByteArray
import com.authlete.cbor.CBORDecoder
import com.authlete.cbor.CBORItem
import com.authlete.cbor.CBORTaggedItem
import com.authlete.cose.COSEProtectedHeaderBuilder
import com.authlete.cose.COSESign1
import com.authlete.cose.COSESign1Builder
import com.authlete.cose.COSESigner
import com.authlete.cose.COSEVerifier
import com.authlete.cose.SigStructureBuilder
import com.authlete.cose.constants.COSEAlgorithms
import com.benasher44.uuid.uuid4
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

val CoseServiceJvmTest by matrixSuite {

    val configurations: List<Pair<EphemeralKey, X509SignatureAlgorithm>> =
        listOf(
            EphemeralKey {
                ec {
                    curve = ECCurve.SECP_256_R_1
                    digests = setOf(curve.nativeDigest)
                }
            }.getOrThrow() to X509SignatureAlgorithm.ES256,

            EphemeralKey {
                ec {
                    curve = ECCurve.SECP_384_R_1
                    digests = setOf(curve.nativeDigest)
                }
            }.getOrThrow() to X509SignatureAlgorithm.ES384,

            EphemeralKey {
                ec {
                    curve = ECCurve.SECP_521_R_1
                    digests = setOf(curve.nativeDigest)
                }
            }.getOrThrow() to X509SignatureAlgorithm.ES512
        )

    configurations.forEach { (ephemeralKey, sigAlgo) ->
        val coseAlgorithm = sigAlgo.toCoseAlgorithm().getOrThrow()
        val extLibAlgorithm = when (sigAlgo) {
            X509SignatureAlgorithm.ES256 -> COSEAlgorithms.ES256
            X509SignatureAlgorithm.ES384 -> COSEAlgorithms.ES384
            X509SignatureAlgorithm.ES512 -> COSEAlgorithms.ES512
            else -> throw IllegalArgumentException("Unknown Algorithm")
        }
        val extLibVerifier = COSEVerifier(ephemeralKey.publicKey.toJcaPublicKey().getOrThrow() as ECPublicKey)

        @OptIn(HazardousMaterials::class)
        val extLibSigner = COSESigner(ephemeralKey.jcaPrivateKey as ECPrivateKey)
        val keyMaterial = EphemeralKeyWithoutCert(ephemeralKey)
        val signCose = SignCose<ByteArray>(keyMaterial)
        val verifierCoseService = VerifyCoseSignatureWithKey<ByteArray>()
        val coseKey = ephemeralKey.publicKey.toCoseKey().getOrThrow()
        val randomPayload = uuid4().toString()

        "$sigAlgo" - {
            "Signed object from int. library can be verified with int. library" {
                val signed = signCose(
                    protectedHeader = null,
                    unprotectedHeader = null,
                    payload = randomPayload.encodeToByteArray(),
                    serializer = ByteArraySerializer()
                ).getOrThrow()

                withClue("Signature: ${signed.signature.encodeToTlv().toDerHexString()}") {
                    verifierCoseService(
                        signed,
                        keyMaterial.publicKey.toCoseKey().getOrThrow(),
                        byteArrayOf(),
                        null
                    ).isSuccess shouldBe true
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
                val coseSigned = extLibCoseSign1.toCoseSigned().apply {
                    payload shouldBe randomPayload.encodeToByteArray()
                }
                val parsedSig = coseSigned.signature.encodeToString()
                val extLibSig = extLibSignature.encodeToString(Base16())

                withClue("Signatures should match\nOurs:\n$parsedSig\nTheirs:\n$extLibSig") {
                    parsedSig shouldBe extLibSig
                }

                val signed = signCose(
                    protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                    unprotectedHeader = null,
                    payload = randomPayload.encodeToByteArray(),
                    serializer = ByteArraySerializer(),
                ).getOrThrow()
                val signedSerialized = signed.serialize(ByteArraySerializer()).encodeToString(Base16())
                val extLibSerialized = extLibCoseSign1.encode().encodeToString(Base16())
                signedSerialized.length shouldBe extLibSerialized.length

                withClue("$sigAlgo: Signature: $parsedSig") {
                    verifierCoseService(coseSigned, coseKey, byteArrayOf(), null).isSuccess shouldBe true
                }
            }

            "Signed object from int. library can be verified with ext. library" {
                val coseSigned = signCose(
                    protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                    unprotectedHeader = null,
                    payload = randomPayload.encodeToByteArray(),
                    serializer = ByteArraySerializer(),
                ).getOrThrow()

                val parsed = coseSigned.toCborTaggedItem()
                    .shouldBeInstanceOf<CBORTaggedItem>()
                val parsedCoseSign1 = parsed.tagContent
                    .shouldBeInstanceOf<COSESign1>()
                val parsedPayload = parsedCoseSign1.payload
                    .shouldBeInstanceOf<CBORByteArray>()

                parsedPayload.value shouldBe randomPayload.encodeToByteArray()
                val parsedSignature = parsedCoseSign1.signature.value.encodeToString(Base16())
                val signature = coseSigned.signature.encodeToString()
                parsedSignature shouldBe signature

                val signatureInput = coseCompliantSerializer.encodeToByteArray(
                    CoseInput.serializer(),
                    CoseInput(
                        contextString = "Signature1",
                        protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                        externalAad = byteArrayOf(),
                        payload = randomPayload.encodeToByteArray(),
                    )
                ).encodeToString(Base16())

                val extLibSigInput = parsedCoseSign1.encodeToString()
                withClue("Our input:\n$signatureInput\n Their input:\n$extLibSigInput") {
                    extLibSigInput shouldBe signatureInput
                }

                withClue("Signature: $parsedSignature") {
                    extLibVerifier.verify(parsedCoseSign1) shouldBe true
                }
            }

            "Signed object from int. library with fully-specified alg cannot be verified with ext. library" {
                val signCoseFullySpecified = SignCose<ByteArray>(
                    keyMaterial,
                    algorithmExtractor = FullySpecifiedCoseHeaderAlgorithmExtractor
                )
                val coseSigned = signCoseFullySpecified(
                    protectedHeader = CoseHeader(algorithm = coseAlgorithm),
                    unprotectedHeader = null,
                    payload = randomPayload.encodeToByteArray(),
                    serializer = ByteArraySerializer(),
                ).getOrThrow()

                val parsed = coseSigned.toCborTaggedItem()
                    .shouldBeInstanceOf<CBORTaggedItem>()
                val parsedCoseSign1 = parsed.tagContent
                    .shouldBeInstanceOf<COSESign1>()

                // Ext. library can not parse fully-specified COSE algorithms
                shouldThrowAny {
                    extLibVerifier.verify(parsedCoseSign1) shouldBe true
                }
            }
        }
    }
}

private fun CryptoSignature.RawByteEncodable.encodeToString(): String =
    (this as CryptoSignature.EC.DefiniteLength).rawByteArray.encodeToString(Base16())

private fun COSESign1.toCoseSigned(): CoseSigned<ByteArray> =
    CoseSigned.deserialize(ByteArraySerializer(), this.encode()).getOrThrow()

private fun COSESign1.encodeToString(): String =
    SigStructureBuilder().sign1(this).build().encode().encodeToString(Base16())

private fun CoseSigned<ByteArray>.toCborTaggedItem(): CBORItem? =
    CBORDecoder(byteArrayOf(0xD2.toByte()) + serialize(ByteArraySerializer())).next()