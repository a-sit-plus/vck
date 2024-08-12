package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

@Suppress("unused")
class OidcSiopCombinedProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String

    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var verifierKeyPair: KeyPairAdapter

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyPair = RandomKeyPairAdapter()
        verifierKeyPair = RandomKeyPairAdapter()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test support for format holder specification" - {

        "test support for plain jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, MobileDrivingLicenceScheme)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    )
                ).let { request ->
                    request.copy(
                        clientMetadata = request.clientMetadata?.let { clientMetadata ->
                            clientMetadata.copy(
                                vpFormats = FormatHolder(
                                    // only allow plain jwt
                                    jwtVp = clientMetadata.vpFormats?.jwtVp
                                )
                            )
                        }
                    )
                }

                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeJwtCredential(holderKeyPair, MobileDrivingLicenceScheme)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }
                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                    )
                ).let { request ->
                    request.copy(
                        clientMetadata = request.clientMetadata?.let { clientMetadata ->
                            clientMetadata.copy(
                                vpFormats = FormatHolder(
                                    // only allow plain jwt
                                    jwtVp = clientMetadata.vpFormats?.jwtVp
                                )
                            )
                        }
                    )
                }

                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val result = verifierSiop.validateAuthnResponse(authnResponse.url)
                result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
                result.vp.verifiableCredentials.shouldNotBeEmpty()
                result.vp.verifiableCredentials.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
            }
        }

        "test support for sd jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    )
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                formats = FormatHolder(
                                    // only support SD_JWT here
                                    jwtSd = presentationDefinition.formats?.jwtSd,
                                ),
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    inputDescriptor.copy(
                                        format = null
                                    )
                                }
                            )
                        },
                    )
                }

                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, MobileDrivingLicenceScheme)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    )
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                formats = FormatHolder(
                                    // only support SD_JWT here
                                    jwtSd = presentationDefinition.formats?.jwtSd,
                                ),
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    inputDescriptor.copy(
                                        format = null
                                    )
                                }
                            )
                        },
                    )
                }

                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val result = verifierSiop.validateAuthnResponse(authnResponse.url)
                result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
                result.sdJwt.type?.shouldContain(ConstantIndex.AtomicAttribute2023.vcType)
            }
        }

        "test support for mso credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, MobileDrivingLicenceScheme)
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    ),
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                // only support msoMdoc here
                                formats = FormatHolder(
                                    msoMdoc = presentationDefinition.formats?.msoMdoc
                                ),
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    inputDescriptor.copy(
                                        format = null
                                    )
                                }
                            )
                        },
                    )
                }
                Napier.d("Create response")

                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow().also {
                        Napier.d("response: $it")
                    }
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeSdJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
                    holderAgent.storeIsoCredential(holderKeyPair, MobileDrivingLicenceScheme)
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = RequestOptions(
                        credentialScheme = ConstantIndex.AtomicAttribute2023,
                        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    ),
                ).let { request ->
                    request.copy(
                        presentationDefinition = request.presentationDefinition?.let { presentationDefinition ->
                            presentationDefinition.copy(
                                formats = FormatHolder(
                                    // only support msoMdoc here
                                    msoMdoc = presentationDefinition.formats?.msoMdoc
                                ),
                                inputDescriptors = presentationDefinition.inputDescriptors.map { inputDescriptor ->
                                    inputDescriptor.copy(
                                        format = null
                                    )
                                }
                            )
                        },
                    )
                }

                Napier.d("request: $authnRequest")
                val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
                authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val result = verifierSiop.validateAuthnResponse(authnResponse.url)
                result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
            }
        }
    }


    "test presentation of multiple credentials with different formats" {
        runBlocking {
            holderAgent.storeJwtCredential(holderKeyPair, ConstantIndex.AtomicAttribute2023)
            holderAgent.storeIsoCredential(holderKeyPair, MobileDrivingLicenceScheme)
        }

        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest1 = verifierSiop.createAuthnRequest(
            requestOptions = RequestOptions(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ),
        )
        val authnRequest2 = verifierSiop.createAuthnRequest(
            requestOptions = RequestOptions(
                credentialScheme = MobileDrivingLicenceScheme,
                representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            ),
        )
        val inputDescriptors2 = authnRequest2.presentationDefinition?.inputDescriptors ?: listOf()

        val authnRequest = authnRequest1.copy(
            presentationDefinition = authnRequest1.presentationDefinition?.let { presentationDefinition ->
                presentationDefinition.copy(
                    inputDescriptors = presentationDefinition.inputDescriptors.map {
                        it.copy(format = presentationDefinition.formats)
                    } + inputDescriptors2.map {
                        it.copy(format = authnRequest2.presentationDefinition?.formats)
                    },
                    formats = null,
                )
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest.serialize()).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        validationResults.validationResults.size shouldBe 2
    }
})

private suspend fun Holder.storeJwtCredential(
    holderKeyPair: KeyPairAdapter,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            RandomKeyPairAdapter(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            holderKeyPair.publicKey,
            credentialScheme,
            ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeSdJwtCredential(
    holderKeyPair: KeyPairAdapter,
    credentialScheme: ConstantIndex.CredentialScheme,
) {
    storeCredential(
        IssuerAgent(
            RandomKeyPairAdapter(),
            DummyCredentialDataProvider(),
        ).issueCredential(
            holderKeyPair.publicKey,
            credentialScheme,
            ConstantIndex.CredentialRepresentation.SD_JWT,
        ).getOrThrow().toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderKeyPair: KeyPairAdapter,
    credentialScheme: ConstantIndex.CredentialScheme,
) = storeCredential(
    IssuerAgent(
        RandomKeyPairAdapter(),
        DummyCredentialDataProvider(),
    ).issueCredential(
        holderKeyPair.publicKey,
        credentialScheme,
        ConstantIndex.CredentialRepresentation.ISO_MDOC,
    ).getOrThrow().toStoreCredentialInput()
)
