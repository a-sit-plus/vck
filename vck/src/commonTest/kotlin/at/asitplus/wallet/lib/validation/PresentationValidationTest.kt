package at.asitplus.wallet.lib.validation

import at.asitplus.iso.DeviceAuth
import at.asitplus.iso.DeviceNameSpaces
import at.asitplus.iso.DeviceSigned
import at.asitplus.iso.Document
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.deviceAuthenticationBytes
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome.Blocked
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.NotApplicable
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import at.asitplus.wallet.lib.validation.ValidationDecision.ACCEPTED
import at.asitplus.wallet.lib.validation.ValidationDecision.REJECTED
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

private const val CHALLENGE = "challenge-1"
private const val AUDIENCE = "x509_hash:verifier"

private fun presentationContext(
    requireHolderBinding: Boolean = true,
    transactionData: List<TransactionDataBase64Url>? = null,
    sessionTranscript: SessionTranscript? = null,
) = PresentationContext(CHALLENGE, AUDIENCE, sessionTranscript, transactionData, requireHolderBinding)

private val PresentationValidationResult.checks get() = report.checks.shouldBeInstanceOf<PresentationChecks>()

private suspend fun Issuance.validatePresentation(
    input: PresentationValidationInput,
    context: PresentationContext = presentationContext(),
    policy: ValidationPolicy = strictPolicy,
) = validator().validate(input, context, policy)

/** The issued SD-JWT with its first disclosure withheld, as the holder presents it. */
private suspend fun Issuance.presentedSdJwt(): String {
    val issued = (issue(CredentialRepresentation.SD_JWT) as Issuer.IssuedCredential.VcSdJwt).signedSdJwtVc
    return (listOf(issued.jws.toString()) + issued.rawDisclosures.drop(1)).joinToString("~", postfix = "~")
}

/** `sd_hash` with the hash function of the credential's `_sd_alg`, which the test issuer chooses at random. */
private fun sdHashOf(sdJwt: String): ByteArray {
    val payload = JwsCompact(sdJwt.substringBefore("~")).getPayload<JsonObject>().getOrThrow()
    return sdJwtDigest(payload["_sd_alg"]?.jsonPrimitive?.content).digest(sdJwt.encodeToByteArray())
}

private suspend fun keyBinding(
    sdJwt: String,
    signer: KeyMaterial,
    challenge: String = CHALLENGE,
    audience: String = AUDIENCE,
    issuedAt: Instant = Clock.System.now(),
    sdHash: ByteArray = sdHashOf(sdJwt),
    transactionDataHashes: List<ByteArray>? = null,
    type: String = JwsContentTypeConstants.KB_JWT,
): String = SignJwt<KeyBindingJws>(signer, JwsHeaderNone())(
    type,
    KeyBindingJws(
        issuedAt = issuedAt,
        audience = audience,
        challenge = challenge,
        sdHash = sdHash,
        transactionDataHashes = transactionDataHashes,
    ),
    KeyBindingJws.serializer(),
).getOrThrow().jws.toString()

private suspend fun Issuance.vpJwt(
    vcs: List<String>,
    signer: KeyMaterial = holderKey,
    issuer: String = signer.publicKey.didEncoded,
    challenge: String = CHALLENGE,
): String {
    val vp = VerifiablePresentation(vcs)
    return SignJwt<VerifiablePresentationJws>(signer, JwsHeaderJwk())(
        null,
        VerifiablePresentationJws(vp, challenge, issuer, AUDIENCE, vp.id),
        VerifiablePresentationJws.serializer(),
    ).getOrThrow().jws.toString()
}

private suspend fun Issuance.vcJwt() =
    (issue(CredentialRepresentation.PLAIN_JWT) as Issuer.IssuedCredential.VcJwt).signedVcJws.jws.toString()

private fun sessionTranscript() = SessionTranscript.forQr(Random.nextBytes(16), Random.nextBytes(16))

/** A document of the issued mdoc, its device signature over [signedTranscript], signed by [signer]. */
private suspend fun Issuance.document(
    signedTranscript: SessionTranscript,
    signer: KeyMaterial = holderKey,
    docType: String = scheme.isoDocType,
): Document {
    val issuerSigned = (issue(CredentialRepresentation.ISO_MDOC) as Issuer.IssuedCredential.Iso).issuerSigned
    val namespaces = ByteStringWrapper(DeviceNameSpaces(emptyMap()))
    val unsigned = Document(docType, issuerSigned, DeviceSigned(namespaces, DeviceAuth()))
    val deviceSignature = SignCoseDetached<ByteArray>(signer)(
        null, null, unsigned.deviceAuthenticationBytes(signedTranscript), ByteArraySerializer()
    ).getOrThrow()
    return unsigned.copy(deviceSigned = DeviceSigned(namespaces, DeviceAuth(deviceSignature = deviceSignature)))
}

val PresentationValidationTest by matrixSuite {

    "SD-JWT" - {
        "with a key binding JWT of the bound key, answering the request, is accepted" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()
            val result = issuance.validatePresentation(
                PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, issuance.holderKey))
            )

            result.report.decision shouldBe ACCEPTED
            result.checks shouldBe PresentationChecks(Passed, Passed, Passed, Passed, Passed, Passed)
            result.report.children.shouldHaveSize(1).single().decision shouldBe ACCEPTED
            result.presentation.shouldBeInstanceOf<ValidatedPresentation.SdJwt>().keyBinding.shouldNotBeNull()
        }

        "without a key binding JWT is rejected if holder binding is required" {
            val issuance = issuance()
            val result = issuance.validatePresentation(PresentationValidationInput.SdJwt(issuance.presentedSdJwt()))

            result.report.decision shouldBe REJECTED
            result.checks.parsing.shouldBeInstanceOf<Failed>()
            result.presentation.shouldBeNull()
        }

        "without holder binding required, the key binding JWT is neither checked nor returned" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()
            val unchecked = keyBinding(sdJwt, EphemeralKeyWithoutCert(), challenge = "another challenge")

            listOf(sdJwt, sdJwt + unchecked).forEach { compact ->
                val result = issuance.validatePresentation(
                    PresentationValidationInput.SdJwt(compact),
                    presentationContext(requireHolderBinding = false),
                )
                result.report.decision shouldBe ACCEPTED
                result.checks.signature shouldBe NotApplicable
                result.presentation.shouldBeInstanceOf<ValidatedPresentation.SdJwt>().keyBinding.shouldBeNull()
            }
        }

        "a key binding JWT signed by another key than cnf fails the signature" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()
            val result = issuance.validatePresentation(
                PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, EphemeralKeyWithoutCert()))
            )

            result.checks.signature.shouldBeInstanceOf<Failed>()
            result.checks.challenge.shouldBeInstanceOf<Blocked>()
        }

        "another nonce, audience, or sd_hash fails" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()
            val key = issuance.holderKey

            issuance.validatePresentation(PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, key, "other")))
                .checks.challenge.shouldBeInstanceOf<Failed>()
            val otherAudience = keyBinding(sdJwt, key, audience = "other")
            issuance.validatePresentation(PresentationValidationInput.SdJwt(sdJwt + otherAudience))
                .checks.audience.shouldBeInstanceOf<Failed>()
            issuance.validatePresentation(
                PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, key, sdHash = Random.nextBytes(32)))
            ).checks.presentationBinding.shouldBeInstanceOf<Failed>()
        }

        "another type of key binding JWT fails parsing" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()

            issuance.validatePresentation(
                PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, issuance.holderKey, type = "jwt"))
            ).checks.parsing.shouldBeInstanceOf<Failed>()
        }

        "the creation time of the key binding JWT is checked with the leeway, whether or not timeliness is required" - {
            listOf(4.minutes to Passed::class, 6.minutes to Failed::class)
                .asData(nameFn = { (age, _) -> "$age old" }) test { (age, expected) ->
                    val issuance = issuance()
                    val sdJwt = issuance.presentedSdJwt()
                    val old = keyBinding(sdJwt, issuance.holderKey, issuedAt = Clock.System.now() - age)
                    listOf(true, false).forEach { requireTimeliness ->
                        issuance.validatePresentation(
                            PresentationValidationInput.SdJwt(sdJwt + old),
                            policy = strictPolicy.copy(requireTimeliness = requireTimeliness),
                        ).checks.proofTime::class shouldBe expected
                    }
                }
        }

        "transaction data requires the key binding JWT to carry its hashes" {
            val issuance = issuance()
            val sdJwt = issuance.presentedSdJwt()
            val transactionData = listOf<TransactionDataBase64Url>(JsonPrimitive("eyJ0eXBlIjoidGVzdCJ9"))
            val hashes = transactionData.map { it.digest(Digest.SHA256) }
            // Transaction data requires holder binding, even if the credential query does not
            val context = presentationContext(requireHolderBinding = false, transactionData = transactionData)

            issuance.validatePresentation(
                PresentationValidationInput.SdJwt(
                    sdJwt + keyBinding(sdJwt, issuance.holderKey, transactionDataHashes = hashes)
                ),
                context,
            ).report.decision shouldBe ACCEPTED
            issuance.validatePresentation(
                PresentationValidationInput.SdJwt(sdJwt + keyBinding(sdJwt, issuance.holderKey)),
                context,
            ).checks.presentationBinding.shouldBeInstanceOf<Failed>()
            issuance.validatePresentation(PresentationValidationInput.SdJwt(sdJwt), context)
                .checks.parsing.shouldBeInstanceOf<Failed>()
        }
    }

    "VP-JWT" - {
        "signed by the holder the credentials are bound to, answering the request, is accepted" {
            val issuance = issuance()
            val vcs = listOf(issuance.vcJwt(), issuance.vcJwt())
            val result = issuance.validatePresentation(PresentationValidationInput.VpJwt(issuance.vpJwt(vcs)))

            result.report.decision shouldBe ACCEPTED
            result.report.children.shouldHaveSize(2)
            result.presentation.shouldBeInstanceOf<ValidatedPresentation.VpJwt>().credentials.shouldHaveSize(2)
        }

        "another nonce fails the challenge" {
            val issuance = issuance()
            val vp = issuance.vpJwt(listOf(issuance.vcJwt()), challenge = "other")

            issuance.validatePresentation(PresentationValidationInput.VpJwt(vp)).checks.challenge
                .shouldBeInstanceOf<Failed>()
        }

        "an iss that does not identify the signing key fails the signature" {
            val issuance = issuance()
            val vp = issuance.vpJwt(listOf(issuance.vcJwt()), issuer = EphemeralKeyWithoutCert().publicKey.didEncoded)

            issuance.validatePresentation(PresentationValidationInput.VpJwt(vp)).checks.signature
                .shouldBeInstanceOf<Failed>()
        }

        "credentials bound to another key than the one that signed the presentation are rejected" {
            val issuance = issuance()
            val vp = issuance.vpJwt(listOf(issuance.vcJwt()), signer = EphemeralKeyWithoutCert())
            val result = issuance.validatePresentation(PresentationValidationInput.VpJwt(vp))

            result.report.decision shouldBe REJECTED
            result.report.children.single().checks.shouldBeInstanceOf<CredentialChecks>().holderBinding
                .shouldBeInstanceOf<Failed>()
        }

        "an unparseable presentation fails parsing, without credentials" {
            val result = issuance().validatePresentation(PresentationValidationInput.VpJwt("not a jws"))

            result.report.decision shouldBe REJECTED
            result.checks.parsing.shouldBeInstanceOf<Failed>()
            result.report.children.shouldBeEmpty()
        }
    }

    "VC-JWT without presentation" - {
        "is rejected if holder binding is required, and accepted otherwise" {
            val issuance = issuance()
            val input = PresentationValidationInput.VcJwt(issuance.vcJwt())

            issuance.validatePresentation(input).checks.signature.shouldBeInstanceOf<Failed>()
            issuance.validatePresentation(input, presentationContext(requireHolderBinding = false)).let {
                it.report.decision shouldBe ACCEPTED
                it.presentation.shouldBeInstanceOf<ValidatedPresentation.VcJwt>()
            }
        }
    }

    "mdoc document" - {
        "with a device signature of the device key over the session transcript is accepted" {
            val issuance = issuance()
            val transcript = sessionTranscript()
            val result = issuance.validatePresentation(
                PresentationValidationInput.MdocDocument(issuance.document(transcript)),
                presentationContext(sessionTranscript = transcript),
            )

            result.report.decision shouldBe ACCEPTED
            result.checks.signature shouldBe Passed
            result.checks.challenge shouldBe NotApplicable
            result.presentation.shouldBeInstanceOf<ValidatedPresentation.MdocDocument>()
        }

        "a device signature over another session transcript, or by another key, fails" {
            val issuance = issuance()
            val transcript = sessionTranscript()

            issuance.validatePresentation(
                PresentationValidationInput.MdocDocument(issuance.document(sessionTranscript())),
                presentationContext(sessionTranscript = transcript),
            ).checks.signature.shouldBeInstanceOf<Failed>()
            issuance.validatePresentation(
                PresentationValidationInput.MdocDocument(issuance.document(transcript, EphemeralKeyWithoutCert())),
                presentationContext(sessionTranscript = transcript),
            ).checks.signature.shouldBeInstanceOf<Failed>()
        }

        "without a session transcript the device signature is blocked" {
            val issuance = issuance()

            val document = issuance.document(sessionTranscript())
            issuance.validatePresentation(PresentationValidationInput.MdocDocument(document))
                .checks.signature.shouldBeInstanceOf<Blocked>()
        }

        "a document type other than the one of the MSO fails the credential's semantics" {
            val issuance = issuance()
            val transcript = sessionTranscript()
            val result = issuance.validatePresentation(
                PresentationValidationInput.MdocDocument(issuance.document(transcript, docType = "org.example.other")),
                presentationContext(sessionTranscript = transcript),
            )

            result.report.decision shouldBe REJECTED
            result.report.children.single().checks.shouldBeInstanceOf<CredentialChecks>().semantics
                .shouldBeInstanceOf<Failed>()
        }
    }

    "a context of a challenge session carries the consumed challenge" {
        val verifier = NonceChallengeVerifier(verifierId = "verifier")
        val request = verifier.createPresentationRequest()

        verifier.consumeChallenge(request.nonce).context(audience = AUDIENCE).challenge shouldBe request.nonce
    }
}
