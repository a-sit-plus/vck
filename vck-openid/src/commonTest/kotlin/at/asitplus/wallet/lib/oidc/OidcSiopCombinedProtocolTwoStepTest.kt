package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

class OidcSiopCombinedProtocolTwoStepTest : FreeSpec({

    lateinit var relyingPartyUrl: String

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial

    lateinit var holderAgent: Holder

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderSiop = OidcSiopWallet(
            keyMaterial = holderKeyMaterial,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyMaterial,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test credential matching" - {
        "only credentials of the correct format are matched" {
            holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            holderAgent.storeIsoCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)
            holderAgent.storeSdJwtCredential(holderKeyMaterial, ConstantIndex.AtomicAttribute2023)

            val authnRequest = verifierSiop.createAuthnRequest(
                requestOptions = OidcSiopVerifier.RequestOptions(
                    credentials = setOf(
                        OidcSiopVerifier.RequestOptionsCredential(
                            ConstantIndex.AtomicAttribute2023,
                            ConstantIndex.CredentialRepresentation.ISO_MDOC
                        )
                    )
                )
            )
            val preparationState = holderSiop.startAuthorizationResponsePreparation(authnRequest.serialize())
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

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023,
                                ConstantIndex.CredentialRepresentation.ISO_MDOC
                            )
                        )
                    )
                )

                val params = holderSiop.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderSiop.startAuthorizationResponsePreparation(params).getOrThrow()
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
                        holderSiop.finalizeAuthorizationResponseParameters(
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
                    val authnRequestSdJwt = verifierSiop.createAuthnRequest(
                        requestOptions = OidcSiopVerifier.RequestOptions(
                            credentials = setOf(
                                OidcSiopVerifier.RequestOptionsCredential(
                                    ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.SD_JWT
                                )
                            )
                        )
                    )

                    val preparationStateSdJwt = holderSiop.startAuthorizationResponsePreparation(
                        holderSiop.parseAuthenticationRequestParameters(authnRequestSdJwt.serialize()).getOrThrow()
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


                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentials = setOf(
                            OidcSiopVerifier.RequestOptionsCredential(
                                ConstantIndex.AtomicAttribute2023, ConstantIndex.CredentialRepresentation.ISO_MDOC
                            )
                        )
                    )
                )

                val params = holderSiop.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderSiop.startAuthorizationResponsePreparation(params).getOrThrow()
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
                    holderSiop.finalizeAuthorizationResponse(
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
        IssuerAgent(
            EphemeralKeyWithoutCert(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ConstantIndex.CredentialRepresentation.SD_JWT,
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyMaterial: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        EphemeralKeyWithSelfSignedCert(),
        DummyCredentialDataProvider(),
    ).issueCredential(
        holderKeyMaterial.publicKey,
        credentialScheme,
        ConstantIndex.CredentialRepresentation.ISO_MDOC,
    ).getOrThrow().toStoreCredentialInput()
)
