package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
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

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey.didEncoded)

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )
    }

    "test support for format holder specification" - {

        "test support for plain jwt credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                }
                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
                    holderAgent.storeJwtCredentials(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeSdJwtCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.AtomicAttribute2023.vcType)
                    )
                    holderAgent.storeIsoCredential(
                        holderCryptoService,
                        listOf(ConstantIndex.MobileDrivingLicence2023.vcType)
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    requestOptions = OidcSiopVerifier.RequestOptions(
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
            holderAgent.storeJwtCredentials(holderCryptoService, listOf(ConstantIndex.AtomicAttribute2023.vcType))
            holderAgent.storeIsoCredential(holderCryptoService, listOf(ConstantIndex.MobileDrivingLicence2023.vcType))
        }

        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest1 = verifierSiop.createAuthnRequest(
            requestOptions = OidcSiopVerifier.RequestOptions(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ),
        )
        val authnRequest2 = verifierSiop.createAuthnRequest(
            requestOptions = OidcSiopVerifier.RequestOptions(
                credentialScheme = ConstantIndex.MobileDrivingLicence2023,
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

private suspend fun Holder.storeJwtCredentials(
    holderCryptoService: CryptoService,
    attributeTypes: List<String>
) {
    storeCredentials(
        IssuerAgent.newDefaultInstance(
            DefaultCryptoService(),
            dataProvider = DummyCredentialDataProvider(),
        ).issueCredential(
            subjectPublicKey = holderCryptoService.publicKey,
            attributeTypes = attributeTypes,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ).toStoreCredentialInput()
    )
}

private suspend fun Holder.storeSdJwtCredential(
    holderCryptoService: CryptoService,
    attributeTypes: List<String>
) {
    storeCredentials(
        IssuerAgent.newDefaultInstance(
            DefaultCryptoService(),
            dataProvider = DummyCredentialDataProvider(),
        ).issueCredential(
            subjectPublicKey = holderCryptoService.publicKey,
            attributeTypes = attributeTypes,
            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
        ).toStoreCredentialInput()
    )
}

private suspend fun Holder.storeIsoCredential(
    holderCryptoService: CryptoService,
    attributeTypes: List<String>
) = storeCredentials(
    IssuerAgent.newDefaultInstance(
        DefaultCryptoService(),
        dataProvider = DummyCredentialDataProvider(),
    ).issueCredential(
        subjectPublicKey = holderCryptoService.publicKey,
        attributeTypes = attributeTypes,
        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
    ).toStoreCredentialInput()
)
