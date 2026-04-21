package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val VerifiablePresentationFactorySdJwtTest by testSuite {

    withFixtureGenerator(suspend {
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
                )
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        object {
            val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
            val sdJwtCredential = sdJwtCredential
        }
    }) - {

        "disclosed SD-JWT contains only one disclosure for one plain disclosed attribute" {
            val disclosedAttributes = listOf(
                NormalizedJsonPath() + "name"
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
    }
}

private val setOfDefaultSdJwtClaims = setOf("iss", "nbf", "exp", "cnf", "vct", "status", "sub", "iat")
