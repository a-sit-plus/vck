package at.asitplus.wallet.lib.openid

import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration.Companion.minutes

class OpenId4VpComplexSdJwtProtocolTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier
    lateinit var randomRegion: String
    lateinit var randomCountry: String

    beforeEach {
        randomRegion = uuid4().toString()
        randomCountry = uuid4().toString()
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                CredentialToBeIssued.VcSd(
                    listOf(
                        ClaimToBeIssued(
                            CLAIM_ADDRESS, listOf(
                                ClaimToBeIssued(CLAIM_ADDRESS_REGION, randomRegion),
                                ClaimToBeIssued(CLAIM_ADDRESS_COUNTRY, randomCountry)
                            )
                        )
                    ),
                    Clock.System.now().plus(5.minutes),
                    AtomicAttribute2023,
                    holderKeyMaterial.publicKey,
                    DummyUserProvider.user,
                )
            ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId)
        )
    }


    "Nested paths with presentation exchange" {
        val requestedClaims = setOf(
            "$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
            "$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
        )
        val requestOptions = OpenIdRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(AtomicAttribute2023, SD_JWT, requestedClaims)
            ),
            presentationMechanism = PresentationMechanismEnum.PresentationExchange
        ).apply {
            toInputDescriptor(FormatContainerJwt(), FormatContainerSdJwt(), null).shouldBeSingleton().first().apply {
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
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions,
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        verifierOid4vp.validateAuthnResponse(authnResponse.url).apply {
            shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
            verifiableCredentialSdJwt.shouldNotBeNull()
            CLAIM_ADDRESS shouldBeIn reconstructed.keys
            reconstructed[CLAIM_ADDRESS].shouldNotBeNull().jsonObject.apply {
                CLAIM_ADDRESS_REGION shouldBeIn this.keys
                this[CLAIM_ADDRESS_COUNTRY].shouldNotBeNull().jsonPrimitive.content shouldBe randomCountry
                this[CLAIM_ADDRESS_REGION].shouldNotBeNull().jsonPrimitive.content shouldBe randomRegion
            }
        }
    }

    "Nested paths with DCQL" {
        val requestedClaims = setOf(
            "$CLAIM_ADDRESS.$CLAIM_ADDRESS_REGION",
            "$CLAIM_ADDRESS.$CLAIM_ADDRESS_COUNTRY"
        )
        val requestOptions = OpenIdRequestOptions(
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
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions,
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        verifierOid4vp.validateAuthnResponse(authnResponse.url).apply {
            shouldBeInstanceOf<AuthnResponseResult.VerifiableDCQLPresentationValidationResults>()
            validationResults.values.shouldBeSingleton().first().apply {
                shouldBeInstanceOf<AuthnResponseResult.SuccessSdJwt>()
                verifiableCredentialSdJwt.shouldNotBeNull()
                CLAIM_ADDRESS shouldBeIn reconstructed.keys
                reconstructed[CLAIM_ADDRESS].shouldNotBeNull().jsonObject.apply {
                    CLAIM_ADDRESS_REGION shouldBeIn this.keys
                    this[CLAIM_ADDRESS_COUNTRY].shouldNotBeNull().jsonPrimitive.content shouldBe randomCountry
                    this[CLAIM_ADDRESS_REGION].shouldNotBeNull().jsonPrimitive.content shouldBe randomRegion
                }
            }
        }
    }

})

private const val CLAIM_ADDRESS = "address"
private const val CLAIM_ADDRESS_REGION = "region"
private const val CLAIM_ADDRESS_COUNTRY = "country"