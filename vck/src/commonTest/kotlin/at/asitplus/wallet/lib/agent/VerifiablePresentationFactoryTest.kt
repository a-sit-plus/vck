@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLClaimsQueryResult.IsoMdocResult
import at.asitplus.openid.dcql.DCQLClaimsQueryResult.JsonResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.JsonPrimitive

val VerifiablePresentationFactoryTest by testSuite {

    withFixtureGenerator(suspend {
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            issuerCredentialStore = InMemoryIssuerCredentialStore(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default,
        )
        val holderCredentialStore = InMemorySubjectCredentialStore()
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holder = HolderAgent(
            keyMaterial = holderKeyMaterial,
            subjectCredentialStore = holderCredentialStore,
        )

        val sdJwtCredential = holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        val isoCredential = holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        object {
            val issuer = issuer
            val holderCredentialStore = holderCredentialStore
            val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
            val sdJwtCredential = sdJwtCredential
            val isoCredential = isoCredential
        }
    }) - {

        "sd-jwt createVerifiablePresentation uses disclosedAttributes (collection)" {
            val disclosedAttributes = listOf(
                NormalizedJsonPath() + CLAIM_GIVEN_NAME,
                NormalizedJsonPath() + CLAIM_FAMILY_NAME,
                NormalizedJsonPath() + "ignored" + CLAIM_DATE_OF_BIRTH,
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
            val result = it.verifiablePresentationFactory.createVerifiablePresentation(
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
            val result = it.verifiablePresentationFactory.createVerifiablePresentation(
                request = presentationRequest(),
                credential = it.isoCredential,
                disclosedAttributes = AllClaimsMatchingResult,
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>().apply {
                disclosedIsoClaimNames(namespace).apply {
                    this shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH, CLAIM_PORTRAIT)
                }
            }
        }

        "iso createVerifiablePresentation uses disclosedAttributes (dcql query results)" {
            val namespace = ConstantIndex.AtomicAttribute2023.isoNamespace.shouldNotBeNull()

            val result = it.verifiablePresentationFactory.createVerifiablePresentation(
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
    }

}

private fun presentationRequest() = PresentationRequestParameters(
    nonce = uuid4().toString(),
    audience = "https://verifier.example.org",
    calcIsoDeviceSignaturePlain = {
        CoseSigned.create(
            CoseHeader(algorithm = CoseAlgorithm.Signature.RS256),
            null,
            byteArrayOf(),
            CryptoSignature.RSA(byteArrayOf()),
            ByteArraySerializer(),
        )
    }
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