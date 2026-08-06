package at.asitplus.wallet.lib.agent

import at.asitplus.iso.SessionTranscript
import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLClaimsQueryResult.IsoMdocResult
import at.asitplus.openid.dcql.DCQLClaimsQueryResult.JsonResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.*
import at.asitplus.openid.dcql.DCQLIsoMdocZkSystemSpec
import at.asitplus.openid.dcql.DCQLIsoMdocZkSystemType
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkBackendRegistry
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

val VerifiablePresentationFactoryTest by matrixSuite {

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
                // Ensure a clean ZK backend registry is being used for these tests.
                // By default, IsoMdocZkEngine uses IsoMdocZkBackendRegistry.Default, which is a global singleton.
                // In a test environment, this can lead to state leakage between tests if backends are registered.
                mdocZkEngine = IsoMdocZkEngine(IsoMdocZkBackendRegistry())
            )
            val sdJwtCredential = issueAndStoreSdJwt(holder, holderKeyMaterial, issuer)
            val isoCredential = issueAndStoreIsoMdoc(holder, holderKeyMaterial, issuer)
            object {
                val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
                val sdJwtCredential = sdJwtCredential
                val isoCredential = isoCredential
            }
        }
    } - {

        "sd-jwt createVerifiablePresentation uses disclosedAttributes (collection)" {
            val disclosedAttributes = listOf(
                NormalizedJsonPath() + CLAIM_GIVEN_NAME,
                NormalizedJsonPath() + CLAIM_FAMILY_NAME,
                NormalizedJsonPath() + CLAIM_DATE_OF_BIRTH,
            )

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.sdJwtCredential,
                disclosedAttributes = disclosedAttributes,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames().apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH) +
                            setOfDefaultSdJwtClaims
                    this.shouldNotContain(CLAIM_PORTRAIT)
                }
        }

        "sd-jwt createVerifiablePresentation with empty disclosedAttributes discloses nothing" {
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.sdJwtCredential,
                disclosedAttributes = emptyList(),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames().apply {
                    this shouldBe setOfDefaultSdJwtClaims
                }
        }

        "sd-jwt createVerifiablePresentation discloses claims of foreign credentials with non-canonical disclosures" {
            // A foreign issuer may serialize disclosures with whitespace: digests are computed over
            // the exact bytes (RFC 9901, section 4.2.3), not over a re-serialization of the parsed item
            val salt = Random.nextBytes(16).encodeToString(Base64UrlStrict)
            val rawDisclosure = """["$salt", "family_name", "Musterfrau"]"""
                .encodeToByteArray().encodeToString(Base64UrlStrict)
            val issuerSignedJws = SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
                JwsContentTypeConstants.SD_JWT,
                buildJsonObject {
                    put("vct", "https://example.com/credentials/unknown")
                    put("_sd", buildJsonArray { add(rawDisclosure.hashDisclosure()) })
                    put("_sd_alg", "sha-256")
                },
                JsonObject.serializer(),
            ).getOrThrow()

            val credential = SubjectCredentialStore.StoreEntry.SdJwt(
                vcSerialized = "${issuerSignedJws.jws}~$rawDisclosure~",
                sdJwt = VerifiableCredentialSdJwt(
                    verifiableCredentialType = "https://example.com/credentials/unknown",
                ),
                disclosures = mapOf(
                    rawDisclosure to SelectiveDisclosureItem(
                        salt = salt.decodeToByteArray(Base64UrlStrict),
                        claimName = "family_name",
                        claimValue = JsonPrimitive("Musterfrau"),
                    )
                ),
                schemeIdentifier = "unknown"
            )

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = credential,
                disclosedAttributes = listOf(NormalizedJsonPath() + "family_name"),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames() shouldContain "family_name"
        }

        "sd-jwt createVerifiablePresentation uses disclosedAttributes (dcql all claims)" {
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.sdJwtCredential,
                disclosedAttributes = AllClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames().apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH, CLAIM_PORTRAIT) +
                            setOfDefaultSdJwtClaims
                }
        }

        "sd-jwt createVerifiablePresentation uses disclosedAttributes (dcql mandatory claims)" {
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.sdJwtCredential,
                disclosedAttributes = AllMandatoryClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames() shouldBe setOfDefaultSdJwtClaims
        }

        "sd-jwt createVerifiablePresentation uses disclosedAttributes (dcql query results)" {
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.sdJwtCredential,
                disclosedAttributes = ClaimsQueryResults(
                    listOf(
                        JsonResult(
                            listOf(NodeListEntry(NormalizedJsonPath() + CLAIM_GIVEN_NAME, JsonPrimitive("x")))
                        ),
                        JsonResult(
                            listOf(NodeListEntry(NormalizedJsonPath() + CLAIM_DATE_OF_BIRTH, JsonPrimitive("y")))
                        ),
                    )
                ),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .disclosedClaimNames().apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH) + setOfDefaultSdJwtClaims
                }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (collection)" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = listOf(
                    NormalizedJsonPath() + namespace + CLAIM_GIVEN_NAME,
                    NormalizedJsonPath() + namespace + CLAIM_FAMILY_NAME,
                    NormalizedJsonPath() + namespace + CLAIM_DATE_OF_BIRTH + "ignored",
                    NormalizedJsonPath() + CLAIM_PORTRAIT,
                ),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                deviceResponse.documents.shouldNotBeNull().shouldHaveSize(1)
                disclosedIsoClaimNames(namespace).apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH)
                    this.shouldNotContain(CLAIM_PORTRAIT)
                }
            }
        }

        "iso createVerifiablePresentation ignores attributes without namespace" {
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = listOf(
                    NormalizedJsonPath() + CLAIM_GIVEN_NAME,
                ),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                deviceResponse.documents.shouldNotBeNull().shouldHaveSize(1)
                disclosedIsoClaimNames(ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()).shouldBeEmpty()
            }
        }

        "iso createVerifiablePresentation throws for unknown disclosedAttributes" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            shouldThrow<PresentationException> {
                it.verifiablePresentationFactory.createVerifiablePresentation(
                    request = presentationRequest(),
                    credential = it.isoCredential,
                    disclosedAttributes = listOf(NormalizedJsonPath() + namespace + "unknown-attribute"),
                ).getOrThrow()
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql all claims)" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()
            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = AllClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                disclosedIsoClaimNames(namespace).apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH, CLAIM_PORTRAIT)
                }
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql mandatory claims)" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = AllMandatoryClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                disclosedIsoClaimNames(namespace).shouldBeEmpty()
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql query results)" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = ClaimsQueryResults(
                    listOf(
                        IsoMdocResult(namespace, CLAIM_GIVEN_NAME, "Susanne"),
                        IsoMdocResult(namespace, CLAIM_PORTRAIT, byteArrayOf(1)),
                    )
                ),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                disclosedIsoClaimNames(namespace) shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_PORTRAIT)
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql query results) and ZKP request with plain fallback" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = ClaimsQueryResults(
                    listOf(
                        IsoMdocResult(namespace, CLAIM_GIVEN_NAME, "Susanne"),
                        IsoMdocResult(namespace, CLAIM_PORTRAIT, byteArrayOf(1)),
                    )
                ),
                zkMetadata = invalidIsoZkMetaData(zkRequired = false)
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                disclosedIsoClaimNames(namespace) shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_PORTRAIT)
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql query results) an ZKP request without fallback" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            shouldThrow<PresentationException> {
                it.verifiablePresentationFactory.createVerifiablePresentation(
                    request = presentationRequest(),
                    credential = it.isoCredential,
                    disclosedAttributes = ClaimsQueryResults(
                        listOf(
                            IsoMdocResult(namespace, CLAIM_GIVEN_NAME, "Susanne"),
                            IsoMdocResult(namespace, CLAIM_PORTRAIT, byteArrayOf(1)),
                        )
                    ),
                    zkMetadata = invalidIsoZkMetaData(zkRequired = true)
                ).getOrThrow()
            }
        }

    }
}
// Simple Session Transcript (mostly empty)
private val simpleTranscriptCallback: () -> SessionTranscript = {
    SessionTranscript.forQr(
        deviceEngagementBytes = byteArrayOf(),
        eReaderKeyBytes = byteArrayOf(),
    )
}

private fun presentationRequest() = PresentationRequestParameters(
    nonce = uuid4().toString(),
    audience = "https://verifier.example.org",
    calcIsoSessionTranscript = simpleTranscriptCallback,
)

private fun CreatePresentationResult.SdJwt.disclosedClaimNames(): Set<String> =
    SdJwtDecoded(sdJwt).reconstructedJsonObject?.keys ?: emptySet()

private fun CreatePresentationResult.DeviceResponse.disclosedIsoClaimNames(namespace: String) =
    deviceResponse.documents.shouldNotBeNull().single()
        .issuerSigned.namespaces
        ?.get(namespace)
        ?.entries
        ?.map { it.value.elementIdentifier }
        ?.toSet()
        ?: emptySet()

private val setOfDefaultSdJwtClaims = setOf("iss", "nbf", "exp", "cnf", "vct", "status", "sub", "iat")

private fun invalidIsoZkMetaData(zkRequired: Boolean) =  ZkMetadata.IsoMdocZk(
    zkInfo = DCQLIsoMdocZkSystemType(
        zkRequired = zkRequired,
        systemSpecs = listOf(
            DCQLIsoMdocZkSystemSpec(
                zkSystemId = "test-id-1",
                system = "non-existant-system",
                circuitHash = "asdf",
                numAttributes = 2,
                version = 12,
            ),
            DCQLIsoMdocZkSystemSpec(
                zkSystemId = "test-id-2",
                system = "non-existant-system",
                circuitHash = "qwerty",
                numAttributes = 3,
                version = 12,
            )
        ),
    )
)