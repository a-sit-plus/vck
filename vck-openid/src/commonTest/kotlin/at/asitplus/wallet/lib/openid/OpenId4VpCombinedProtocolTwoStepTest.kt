package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationExchangeCredentialDisclosure
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OpenId4VpCombinedProtocolTwoStepTest : FreeSpec({

    lateinit var clientId: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderOid4vp = OpenId4VpHolder(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
            randomSource = RandomSource.Default,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
    }

    "test credential matching" - {
        "only credentials of the correct format are matched" {
            holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
            holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
            holderAgent.storeSdJwtCredential(holderKeyMaterial, AtomicAttribute2023)

            val authnRequest = verifierOid4vp.createAuthnRequest(
                requestOptions = RequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    )
                )
            )
            val preparationState = holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                .getOrThrow()
            val presentationDefinition = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<PresentationExchangeRequest>()
                .presentationDefinition
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

            holderAgent.matchInputDescriptorsAgainstCredentialStore(presentationDefinition.inputDescriptors)
                .getOrThrow()[inputDescriptorId]
                .shouldNotBeNull().apply {
                    this shouldHaveSize 2
                    keys.forEach {
                        it.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
                    }
                }
        }
    }

    "test credential submission" - {
        "submission requirements need to match" - {
            "all credentials matching an input descriptor should be presentable" {
                holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                        )
                    )
                )

                val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderOid4vp.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationExchangeRequest = preparationState.credentialPresentationRequest
                    .shouldBeInstanceOf<PresentationExchangeRequest>()
                val presentationDefinition = presentationExchangeRequest.presentationDefinition

                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors
                ).getOrThrow().also { it shouldHaveSize 1 }

                val inputDescriptorMatches = matches[inputDescriptorId].shouldNotBeNull()
                    .also { it shouldHaveSize 2 }

                inputDescriptorMatches.forEach {
                    val submission = mapOf(
                        inputDescriptorId to PresentationExchangeCredentialDisclosure(
                            credential = it.key,
                            disclosedAttributes = it.value.mapNotNull {
                                it.value.firstOrNull()?.normalizedJsonPath
                            }
                        )
                    )

                    shouldNotThrowAny {
                        holderOid4vp.finalizeAuthorizationResponseParameters(
                            request = params,
                            clientMetadata = verifierOid4vp.metadata,
                            credentialPresentation = PresentationExchangePresentation(
                                presentationRequest = presentationExchangeRequest,
                                inputDescriptorSubmissions = submission
                            )
                        ).getOrThrow()
                    }
                }
            }

            "not all optional claims need to be presented" {
                holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(
                                credentialScheme = AtomicAttribute2023,
                                representation = ISO_MDOC,
                                requestedOptionalAttributes = setOf(
                                    AtomicAttribute2023.CLAIM_FAMILY_NAME,
                                    AtomicAttribute2023.CLAIM_GIVEN_NAME
                                )
                            ),
                        )
                    )
                )

                val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderOid4vp.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationExchangeRequest = preparationState.credentialPresentationRequest
                    .shouldBeInstanceOf<PresentationExchangeRequest>()
                val presentationDefinition = presentationExchangeRequest.presentationDefinition

                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors
                ).getOrThrow().also { it shouldHaveSize 1 }

                matches[inputDescriptorId].shouldNotBeNull().entries
                    .shouldBeSingleton().first().apply {
                        val submission = mapOf(
                            inputDescriptorId to PresentationExchangeCredentialDisclosure(
                                credential = key,
                                disclosedAttributes = value.mapNotNull {
                                    it.value.firstOrNull()?.normalizedJsonPath
                                        .takeIf { it.toString().contains(AtomicAttribute2023.CLAIM_GIVEN_NAME) }
                                }
                            )
                        )

                        shouldNotThrowAny {
                            holderOid4vp.finalizeAuthorizationResponseParameters(
                                request = params,
                                clientMetadata = verifierOid4vp.metadata,
                                credentialPresentation = PresentationExchangePresentation(
                                    presentationRequest = presentationExchangeRequest,
                                    inputDescriptorSubmissions = submission
                                )
                            ).getOrThrow()
                        }
                    }
            }


            "credentials not matching an input descriptor should not yield a valid submission" {
                holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, AtomicAttribute2023)

                val sdJwtMatches = run {
                    val authnRequestSdJwt = verifierOid4vp.createAuthnRequest(
                        requestOptions = RequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(AtomicAttribute2023, SD_JWT)
                            )
                        )
                    )

                    val preparationStateSdJwt = holderOid4vp.startAuthorizationResponsePreparation(
                        holderOid4vp.parseAuthenticationRequestParameters(authnRequestSdJwt.serialize()).getOrThrow()
                    ).getOrThrow()
                    val presentationDefinitionSdJwt = preparationStateSdJwt.credentialPresentationRequest
                        .shouldBeInstanceOf<PresentationExchangeRequest>()
                        .presentationDefinition

                    holderAgent.matchInputDescriptorsAgainstCredentialStore(
                        presentationDefinitionSdJwt.inputDescriptors,
                    ).getOrThrow().also {
                        it.shouldHaveSize(1)
                        it.entries.first().value.let {
                            it.shouldHaveSize(1)
                            it.entries.forEach {
                                it.key.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()
                            }
                        }
                    }
                }


                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                        )
                    )
                )

                val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderOid4vp.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationExchangeRequest = preparationState.credentialPresentationRequest
                    .shouldBeInstanceOf<PresentationExchangeRequest>()
                val presentationDefinition = presentationExchangeRequest
                    .presentationDefinition
                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors,
                ).getOrThrow().also {
                    it shouldHaveSize 1
                }

                matches[inputDescriptorId].shouldNotBeNull().shouldHaveSize(2)

                val submission = mapOf(
                    inputDescriptorId to sdJwtMatches.values.first().entries.first().let {
                        PresentationExchangeCredentialDisclosure(
                            credential = it.key,
                            disclosedAttributes = it.value.entries.mapNotNull {
                                it.value.firstOrNull()?.normalizedJsonPath
                            }
                        )
                    }
                )

                shouldThrowAny {
                    holderOid4vp.finalizeAuthorizationResponse(
                        request = params,
                        clientMetadata = verifierOid4vp.metadata,
                        credentialPresentation = PresentationExchangePresentation(
                            presentationRequest = presentationExchangeRequest,
                            inputDescriptorSubmissions = submission
                        )
                    ).getOrThrow()
                }
            }
        }
    }
})

private suspend fun Holder.storeSdJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                credentialScheme,
                SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        keyMaterial = EphemeralKeyWithSelfSignedCert(),
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    ).issueCredential(
        DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().toStoreCredentialInput()
)

private fun AuthenticationRequestParameters.serialize(): String = vckJsonSerializer.encodeToString(this)
