package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
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
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpCombinedProtocolTwoStepTest by testSuite {

    withFixtureGenerator {
        object {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val clientId: String = "https://example.com/rp/${uuid4()}"
            val holderAgent: Holder = HolderAgent(holderKeyMaterial)
            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                keyMaterial = holderKeyMaterial,
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            )
        }
    } - {

        test("matching: only credentials of the correct format are matched") {
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    )
                )
            )
            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                .getOrThrow()
            val presentationDefinition = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<PresentationExchangeRequest>()
                .presentationDefinition
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

            it.holderAgent.matchInputDescriptorsAgainstCredentialStore(presentationDefinition.inputDescriptors)
                .getOrThrow()[inputDescriptorId]
                .shouldNotBeNull().apply {
                    this shouldHaveSize 2
                    keys.forEach {
                        it.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
                    }
                }
        }

        test("submission requirements need to match: all credentials matching an input descriptor should be presentable") {
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    )
                )
            )

            val preparationState =
                it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                    .getOrThrow()
            val presentationExchangeRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<PresentationExchangeRequest>()
            val presentationDefinition = presentationExchangeRequest.presentationDefinition

            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
            val matches = it.holderAgent.matchInputDescriptorsAgainstCredentialStore(
                presentationDefinition.inputDescriptors
            ).getOrThrow().also { it shouldHaveSize 1 }

            val inputDescriptorMatches = matches[inputDescriptorId].shouldNotBeNull()
                .also { it shouldHaveSize 2 }

            val fx = it
            inputDescriptorMatches.forEach { match ->
                val submission = mapOf(
                    inputDescriptorId to PresentationExchangeCredentialDisclosure(
                        credential = match.key,
                        disclosedAttributes = match.value.mapNotNull { attr ->
                            attr.value.firstOrNull()?.normalizedJsonPath
                        }
                    )
                )

                shouldNotThrowAny {
                    fx.holderOid4vp.finalizeAuthorizationResponse(
                        preparationState = preparationState,
                        credentialPresentation = PresentationExchangePresentation(
                            presentationRequest = presentationExchangeRequest,
                            inputDescriptorSubmissions = submission
                        )
                    ).getOrThrow()
                }
            }
        }

        test("submission requirements need to match: not all optional claims need to be presented") {
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
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

            val preparationState =
                it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                    .getOrThrow()
            val presentationExchangeRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<PresentationExchangeRequest>()
            val presentationDefinition = presentationExchangeRequest.presentationDefinition

            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
            val matches = it.holderAgent.matchInputDescriptorsAgainstCredentialStore(
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
                        it.holderOid4vp.finalizeAuthorizationResponse(
                            preparationState = preparationState,
                            credentialPresentation = PresentationExchangePresentation(
                                presentationRequest = presentationExchangeRequest,
                                inputDescriptorSubmissions = submission
                            )
                        ).getOrThrow()
                    }
                }
        }


        test("submission requirements need to match: credentials not matching an input descriptor should not yield a valid submission") {
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeIsoCredential(it.holderKeyMaterial, AtomicAttribute2023)
            it.holderAgent.storeSdJwtCredential(it.holderKeyMaterial, AtomicAttribute2023)

            val sdJwtMatches = run {
                val authnRequestSdJwt = it.verifierOid4vp.createAuthnRequest(
                    requestOptions = OpenId4VpRequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(AtomicAttribute2023, SD_JWT)
                        )
                    )
                )

                val preparationStateSdJwt =
                    it.holderOid4vp.startAuthorizationResponsePreparation(authnRequestSdJwt.serialize())
                        .getOrThrow()
                val presentationDefinitionSdJwt = preparationStateSdJwt.credentialPresentationRequest
                    .shouldBeInstanceOf<PresentationExchangeRequest>()
                    .presentationDefinition

                it.holderAgent.matchInputDescriptorsAgainstCredentialStore(
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


            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    )
                )
            )

            val preparationState =
                it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                    .getOrThrow()
            val presentationExchangeRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<PresentationExchangeRequest>()
            val presentationDefinition = presentationExchangeRequest
                .presentationDefinition
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

            val matches = it.holderAgent.matchInputDescriptorsAgainstCredentialStore(
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

            it.holderOid4vp.finalizeAuthorizationResponse(
                preparationState = preparationState,
                credentialPresentation = PresentationExchangePresentation(
                    presentationRequest = presentationExchangeRequest,
                    inputDescriptorSubmissions = submission
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }
    }
}

private suspend fun Holder.storeSdJwtCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
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
