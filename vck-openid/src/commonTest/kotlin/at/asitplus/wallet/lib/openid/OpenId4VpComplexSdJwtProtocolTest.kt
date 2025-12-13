package at.asitplus.wallet.lib.openid

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.jsonpath.JsonPath
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

val OpenId4VpComplexSdJwtProtocolTest by testSuite {

    withFixtureGenerator(suspend {
        val randomRegion = uuid4().toString()
        val randomCountry = uuid4().toString()
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKeyMaterial).also {
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    CredentialToBeIssued.VcSd(
                        claims = listOf(
                            ClaimToBeIssued(
                                CLAIM_ADDRESS, listOf(
                                    ClaimToBeIssued(CLAIM_ADDRESS_REGION, randomRegion),
                                    ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, randomCountry)
                                )
                            )
                        ),
                        expiration = Clock.System.now().plus(5.minutes),
                        scheme = AtomicAttribute2023,
                        subjectPublicKey = holderKeyMaterial.publicKey,
                        userInfo = DummyUserProvider.user,
                        sdAlgorithm = supportedSdAlgorithms.random(),
                    )
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {

            val randomRegion = randomRegion
            val randomCountry = randomCountry

            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            val clientId = "https://example.com/rp/${uuid4()}"
            val walletUrl = "https://example.com/wallet/${uuid4()}"

            val holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId)
            )
        }
    }) - {

        "Nested paths with presentation exchange" {
            val requestedClaims = setOf(
                "$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
                "$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, requestedClaims)
                ),
                presentationMechanism = PresentationMechanismEnum.PresentationExchange
            ).apply {
                toInputDescriptor(FormatContainerJwt(), FormatContainerSdJwt()).shouldBeSingleton().first().apply {
                    constraints.shouldNotBeNull().apply {
                        fields.shouldNotBeNull().forEach {
                            it.path.shouldBeSingleton().first().apply {
                                JsonPath(this)
                                if (!this.contains("vct"))
                                    split(".").shouldHaveSize(3) // "$", first segment, second segment
                            }
                        }
                    }
                }
            }
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions,
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).apply {
                shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                verifiableCredentialSdJwt.shouldNotBeNull()
                CLAIM_ADDRESS shouldBeIn reconstructed.keys
                reconstructed[CLAIM_ADDRESS].shouldNotBeNull().jsonObject.apply {
                    CLAIM_ADDRESS_REGION shouldBeIn this.keys
                    this[CLAIM_ADDRESS_COUNTRY].shouldNotBeNull().jsonPrimitive.content shouldBe it.randomCountry
                    this[CLAIM_ADDRESS_REGION].shouldNotBeNull().jsonPrimitive.content shouldBe it.randomRegion
                }
            }
        }

        "Nested paths with DCQL" {
            val requestedClaims = setOf(
                "$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
                "$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
            )
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(AtomicAttribute2023, SD_JWT, requestedClaims)
                ),
                presentationMechanism = PresentationMechanismEnum.DCQL
            ).apply {
                toDCQLQuery().shouldNotBeNull().apply {
                    credentials.shouldBeSingleton().first().apply {
                        claims.shouldNotBeNull().forEach {
                            it.path.shouldNotBeNull().shouldHaveSize(2)
                        }
                    }
                }
            }
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions,
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).apply {
                shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
                validationResults.values.shouldBeSingleton().first().apply {
                    shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    CLAIM_ADDRESS shouldBeIn reconstructed.keys
                    reconstructed[CLAIM_ADDRESS].shouldNotBeNull().jsonObject.apply {
                        CLAIM_ADDRESS_REGION shouldBeIn this.keys
                        this[CLAIM_ADDRESS_COUNTRY].shouldNotBeNull().jsonPrimitive.content shouldBe it.randomCountry
                        this[CLAIM_ADDRESS_REGION].shouldNotBeNull().jsonPrimitive.content shouldBe it.randomRegion
                    }
                }
            }
        }
    }
}


private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"