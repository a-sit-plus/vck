package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.csc.bindings.QesApprovalBinding
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.decodeFromString
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val VerifiablePresentationFactorySdJwtTest by matrixSuite {

    fixture {
        runBlocking {
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(
                keyMaterial = holderKeyMaterial,
            )

            val sdJwtCredential = holder.storeCredential(
                issuer.issueCredential(
                    CredentialToBeIssued.VcSd(
                        claims = listOf(
                            ClaimToBeIssued("name", "Winston Smith"),
                            ClaimToBeIssued(
                                "birthplace",
                                listOf(
                                    ClaimToBeIssued("city", "Vienna"),
                                    ClaimToBeIssued("country", "Austria")
                                )
                            ),
                            ClaimToBeIssued(
                                "address",
                                listOf(
                                    ClaimToBeIssued("city", "London"),
                                    ClaimToBeIssued("country", "Oceania")
                                )
                            )
                        ),
                        expiration = Clock.System.now() + 5.minutes,
                        scheme = ConstantIndex.AtomicAttribute2023,
                        subjectPublicKey = holderKeyMaterial.publicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                        sdAlgorithm = Digest.SHA384,
                    )
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            object {
                val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
                val sdJwtCredential = sdJwtCredential
            }
        }
    } - {

        "disclosed SD-JWT contains only one disclosure for one plain disclosed attribute" {
            val disclosedAttributes = listOf(
                NormalizedJsonPath() + "name"
            )
            val request = PresentationRequestParameters(
                nonce = uuid4().toString(),
                audience = "https://verifier.example.org",
            )
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = request,
                credential = it.sdJwtCredential,
                disclosedAttributes = disclosedAttributes,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>().apply {
                sdJwt.keyBindingJws.shouldNotBeNull().payload.sdHash.size shouldBe 48
                ValidatorSdJwt().verifyVpSdJwt(sdJwt, request.nonce, request.audience, null).getOrThrow()
                SdJwtDecoded(sdJwt).apply {
                    validDisclosures.shouldHaveSize(1)
                    reconstructedJsonObject.shouldNotBeNull().keys shouldBe setOf("name") + setOfDefaultSdJwtClaims
                }
            }
        }
        "disclosed SD-JWT contains only two disclosures for one disclosed nested attribute" {
            val disclosedAttributes = listOf(
                NormalizedJsonPath() + "address" + "city",
            )
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = PresentationRequestParameters(
                    nonce = uuid4().toString(),
                    audience = "https://verifier.example.org",
                ),
                credential = it.sdJwtCredential,
                disclosedAttributes = disclosedAttributes,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>().apply {
                SdJwtDecoded(sdJwt).apply {
                    // for "city" inside "address" and "address" itself, but not for "city" inside "birthplace"
                    validDisclosures.shouldHaveSize(2)
                    reconstructedJsonObject.shouldNotBeNull().apply {
                        keys shouldBe setOf("address") + setOfDefaultSdJwtClaims
                        get("address").shouldNotBeNull().let { address ->
                            address.jsonObject["city"].shouldNotBeNull().jsonPrimitive.content shouldBe "London"
                            address.jsonObject.containsKey("country") shouldBe false
                        }
                        containsKey("birthplace") shouldBe false
                    }
                }
            }
        }
        "QES approval is hashed over encoded transaction_data in the SD-JWT Key Binding JWT" {
            val approvalJson = """{"type":"https://cloudsignatureconsortium.org/2025/qes-approval","credential_ids":["approval-credential"],"signatureQualifier":"eu_eidas_qes","numSignatures":1,"documentDigests":[{"label":"Contract","hash":"AQID"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"}"""
            val encodedTransactionData = approvalJson.encodeToByteArray().encodeToString(Base64UrlStrict)
            val request = PresentationRequestParameters(
                nonce = uuid4().toString(),
                audience = "https://verifier.example.org",
                transactionData = listOf(JsonPrimitive(encodedTransactionData)),
            )

            val result = it.verifiablePresentationFactory.createVerifiablePresentation(
                request = request,
                credential = it.sdJwtCredential,
                disclosedAttributes = emptyList(),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val expectedDigest = Digest.SHA256.digest(encodedTransactionData.encodeToByteArray())
            val keyBinding = result.sdJwt.keyBindingJws.shouldNotBeNull()
            keyBinding.payload.qesApproval.shouldNotBeNull().contentEquals(expectedDigest) shouldBe true

            val payloadJson = keyBinding.toString().split('.')[1]
                .decodeToByteArray(Base64UrlStrict).decodeToString()
            val encodedApproval = Json.parseToJsonElement(payloadJson).jsonObject
                .getValue(QesApprovalBinding.SD_JWT_CLAIM).jsonPrimitive.content
            Json.decodeFromString(ByteArrayBase64Serializer, "\"$encodedApproval\"")
                .contentEquals(expectedDigest) shouldBe true
        }
    }
}

private val setOfDefaultSdJwtClaims = setOf("iss", "nbf", "exp", "cnf", "vct", "status", "sub", "iat")
