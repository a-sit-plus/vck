package at.asitplus.wallet.lib.oidc

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.wallet.lib.agent.CredentialSubmission
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.dif.FormatHolder
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

class OidcSiopCombinedProtocolTwoStepTest : FreeSpec({

    lateinit var relyingPartyUrl: String

    lateinit var holderKeyPair: KeyMaterial
    lateinit var verifierKeyPair: KeyMaterial

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyPair = EphemeralKeyWithSelfSignedCert()
        verifierKeyPair = EphemeralKeyWithSelfSignedCert()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)

        holderSiop = OidcSiopWallet(
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier(
            keyMaterial = verifierKeyPair,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test credential matching" - {
        "only credentials of the correct format are matched" {
            runBlocking {
                holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
            }

            verifierSiop = OidcSiopVerifier(
                keyMaterial = verifierKeyPair,
                relyingPartyUrl = relyingPartyUrl,
            )

            val authnRequest = verifierSiop.createAuthnRequest(
                requestOptions = OidcSiopVerifier.RequestOptions(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                )
            ).let { request ->
                request.copy(
                    presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                        presentationDefinition.copy(
                            // only support msoMdoc here
                            formats = FormatHolder(
                                msoMdoc = presentationDefinition.formats?.msoMdoc
                            ),
                            inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                (inputDescriptor as DifInputDescriptor).copy(format = null)
                            }
                        )
                    },
                )
            }
            val preparationState = holderSiop.startAuthorizationResponsePreparation(authnRequest.serialize())
                .getOrThrow()
            val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
            val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

            val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                presentationDefinition.inputDescriptors,
                presentationDefinition.formats,
            ).getOrThrow()
            val inputDescriptorMatches = matches[inputDescriptorId].shouldNotBeNull()
            inputDescriptorMatches shouldHaveSize 2
            inputDescriptorMatches.keys.forEach {
                it.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
            }
        }
    }

    "test credential submission" - {
        "submission requirements need to macth" - {
            "all credentials matching an input descriptor should be presentable" {
                runBlocking {
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }

                verifierSiop = OidcSiopVerifier(
                    keyMaterial = verifierKeyPair,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    )
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                // only support msoMdoc here
                                formats = FormatHolder(
                                    msoMdoc = presentationDefinition.formats?.msoMdoc
                                ),
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    (inputDescriptor as DifInputDescriptor).copy(
                                        format = null
                                    )
                                }
                            )
                        },
                    )
                }

                val params = holderSiop.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderSiop.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id
                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors,
                    presentationDefinition.formats,
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
                runBlocking {
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }

                verifierSiop = OidcSiopVerifier(
                    keyMaterial = verifierKeyPair,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val sdJwtMatches = run {
                    val authnRequestSdJwt = verifierSiop.createAuthnRequest(
                        requestOptions = OidcSiopVerifier.RequestOptions(
                            credentialScheme = ConstantIndex.AtomicAttribute2023,
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        )
                    ).let { request ->
                        request.copy(
                            presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                                presentationDefinition.copy(
                                    // only support msoMdoc here
                                    inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                        (inputDescriptor as DifInputDescriptor).copy(
                                            format = FormatHolder(
                                                jwtSd = presentationDefinition.formats?.jwtSd
                                            ),
                                        )
                                    }
                                )
                            },
                        )
                    }

                    val preparationStateSdJwt = holderSiop.startAuthorizationResponsePreparation(
                        holderSiop.parseAuthenticationRequestParameters(authnRequestSdJwt.serialize()).getOrThrow()
                    ).getOrThrow()
                    val presentationDefinitionSdJwt = preparationStateSdJwt.presentationDefinition.shouldNotBeNull()

                    holderAgent.matchInputDescriptorsAgainstCredentialStore(
                        presentationDefinitionSdJwt.inputDescriptors,
                        presentationDefinitionSdJwt.formats,
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
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    )
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                // only support msoMdoc here
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    (inputDescriptor as DifInputDescriptor).copy(
                                        format = FormatHolder(
                                            msoMdoc = presentationDefinition.formats?.msoMdoc
                                        ),
                                    )
                                }
                            )
                        },
                    )
                }

                val params = holderSiop.parseAuthenticationRequestParameters(authnRequest.serialize()).getOrThrow()
                val preparationState = holderSiop.startAuthorizationResponsePreparation(params).getOrThrow()
                val presentationDefinition = preparationState.presentationDefinition.shouldNotBeNull()
                val inputDescriptorId = presentationDefinition.inputDescriptors.first().id

                val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                    presentationDefinition.inputDescriptors,
                    presentationDefinition.formats,
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
    holderKeyPair: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            EphemeralKeyWithSelfSignedCert(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            holderKeyPair.publicKey,
            credentialScheme,
            ConstantIndex.CredentialRepresentation.SD_JWT,
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyPair: KeyMaterial,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        EphemeralKeyWithSelfSignedCert(),
        DummyCredentialDataProvider(),
    ).issueCredential(
        holderKeyPair.publicKey,
        credentialScheme,
        ConstantIndex.CredentialRepresentation.ISO_MDOC,
    ).getOrThrow().toStoreCredentialInput()
)
