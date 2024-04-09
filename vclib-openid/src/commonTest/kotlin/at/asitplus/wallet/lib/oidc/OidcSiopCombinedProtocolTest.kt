package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JwsSigned
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
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondBadRequest
import io.ktor.client.engine.mock.respondRedirect
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.runBlocking

@Suppress("unused")
class OidcSiopCombinedProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

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
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey.didEncoded)

        holderSiop = OidcSiopWallet.newInstance(
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
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
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
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                }
            }

            "if available despite others" {
                runBlocking {
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }
                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
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

                val authnResponse =
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
                validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
                val result = validationResults.validationResults.first()
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
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
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
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
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

                val authnResponse =
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
                validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
                val result = validationResults.validationResults.first()
                result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt>()
                result.sdJwt.type.contains(ConstantIndex.AtomicAttribute2023.vcType)
            }
        }

        "test support for mso credential request" - {
            "if not available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
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

                shouldThrow<OAuth2Exception> {
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                }
            }

            "if available despite others with correct format or correct attribute, but not both" {
                runBlocking {
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                    holderAgent.storeCredentials(
                        IssuerAgent.newDefaultInstance(
                            DefaultCryptoService(),
                            dataProvider = DummyCredentialDataProvider(),
                        ).issueCredential(
                            subjectPublicKey = holderCryptoService.publicKey,
                            attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                        ).toStoreCredentialInput()
                    )
                }

                verifierSiop = OidcSiopVerifier.newInstance(
                    verifier = verifierAgent,
                    cryptoService = verifierCryptoService,
                    relyingPartyUrl = relyingPartyUrl,
                )

                val authnRequest = verifierSiop.createAuthnRequest(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
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

                val authnResponse =
                    holderSiop.createAuthnResponse(authnRequest).getOrThrow()
                authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
                    .also { println(it) }

                val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
                validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
                val result = validationResults.validationResults.first()
                result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.SuccessIso>()
            }
        }
    }


    "test presentation of multiple credentials with different formats" {
        runBlocking {
            holderAgent.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).toStoreCredentialInput()
            )
            holderAgent.storeCredentials(
                IssuerAgent.newDefaultInstance(
                    DefaultCryptoService(),
                    dataProvider = DummyCredentialDataProvider(),
                ).issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.MobileDrivingLicence2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ).toStoreCredentialInput()
            )
        }

        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest1 = verifierSiop.createAuthnRequest(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        )
        val authnRequest2 = verifierSiop.createAuthnRequest(
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
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

        val authnResponse =
            holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        validationResults.validationResults.size shouldBe 2
    }
})