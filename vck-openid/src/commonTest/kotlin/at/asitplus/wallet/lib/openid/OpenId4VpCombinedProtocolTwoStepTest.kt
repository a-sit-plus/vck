package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
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
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
        )
    }

    "test credential matching" - {
        "only credentials of the correct format are matched" {
            holderAgent.storeIsoCredential(holderKeyMaterial, AtomicAttribute2023)
            holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = verifierOid4vp.createAuthnRequest(
                requestOptions = OpenIdRequestOptions(
                    credentials = setOf(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                    )
                )
            )
            val preparationState = holderOid4vp.startAuthorizationResponsePreparation(authnRequest.serialize())
                .getOrThrow()
            val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

            val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                presentationDefinition.inputDescriptors
            ).getOrThrow()
            val inputDescriptorMatches = matches[inputDescriptorId].shouldNotBeNull()
            inputDescriptorMatches shouldHaveSize 2
            inputDescriptorMatches.keys.forEach {
                it.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
            }
        }
    }

    "test credential submission" - {
        "submission requirements need to match" - {
            "all credentials matching an input descriptor should be presentable" {
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val authnRequest = verifierOid4vp.createAuthnRequest(
                    requestOptions = OpenIdRequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        )
                    )
                )

                val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderOid4vp.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors
                ).getOrThrow().also {
                    it shouldHaveSize 1
                }

                val inputDescriptorMatches = matches[inputDescriptorId].shouldNotBeNull()
                    .also { it shouldHaveSize 2 }

                inputDescriptorMatches.forEach {
                    val submission = mapOf(
                        inputDescriptorId to CredentialSubmission(
                            credential = it.key,
                            disclosedAttributes = it.value.mapNotNull {
                                it.value.firstOrNull()?.normalizedJsonPath
                            }
                        )
                    )

                    shouldNotThrowAny {
                        holderOid4vp.finalizeAuthorizationResponseParameters(
                            preparationState = preparationState,
                            request = params,
                            inputDescriptorSubmissions = submission
                        ).getOrThrow()
                    }
                }
            }
            "credentials not matching an input descriptor should not yield a valid submission" {
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

                val sdJwtMatches = run {
                    val authnRequestSdJwt = verifierOid4vp.createAuthnRequest(
                        requestOptions = OpenIdRequestOptions(
                            credentials = setOf(
                                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, SD_JWT)
                            )
                        )
                    )

                    val preparationStateSdJwt = holderOid4vp.startAuthorizationResponsePreparation(
                        holderOid4vp.parseAuthenticationRequestParameters(authnRequestSdJwt.serialize()).getOrThrow()
                    ).getOrThrow()
                    val presentationDefinitionSdJwt = preparationStateSdJwt.presentationDefinition.shouldNotBeNull()

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
                    requestOptions = OpenIdRequestOptions(
                        credentials = setOf(
                            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023, ISO_MDOC)
                        )
                    )
                )

                val params = holderOid4vp.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderOid4vp.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors,
                ).getOrThrow().also {
                    it shouldHaveSize 1
                }

                matches[inputDescriptorId].shouldNotBeNull().shouldHaveSize(2)

                val submission = mapOf(
                    inputDescriptorId to sdJwtMatches.values.first().entries.first().let {
                        CredentialSubmission(
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
                        preparationState = preparationState,
                        inputDescriptorSubmissions = submission
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
        IssuerAgent().issueCredential(
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
    IssuerAgent(EphemeralKeyWithSelfSignedCert()).issueCredential(
        DummyCredentialDataProvider.getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow().toStoreCredentialInput()
)