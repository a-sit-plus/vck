package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
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
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
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
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

@Suppress("unused")
class OidcSiopProtocolTest : FreeSpec({

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
        }

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

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl = walletUrl)
            .also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        /* TODO: re-evaluate after rebase
        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
        */
        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()

        verifySecondProtocolRun(verifierSiop, walletUrl, holderSiop)
    }

    "test with QR Code" {
        val metadataUrlNonce = uuid4().toString()
        val metadataUrl = "https://example.com/$metadataUrlNonce"
        val requestUrlNonce = uuid4().toString()
        val requestUrl = "https://example.com/$requestUrlNonce"
        val qrcode = verifierSiop.createQrCodeUrl(walletUrl, metadataUrl, requestUrl)
        qrcode shouldContain metadataUrlNonce
        qrcode shouldContain requestUrlNonce

        val metadataObject = verifierSiop.createSignedMetadata().getOrThrow()
            .also { println(it) }
        DefaultVerifierJwsService().verifyJwsObject(metadataObject).shouldBeTrue()

        val authnRequestUrl =
            verifierSiop.createAuthnRequestUrlWithRequestObject(walletUrl).getOrThrow()
        val authnRequest: AuthenticationRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jar)!!).shouldBeTrue()

        val authnResponse = holderSiop.createAuthnResponse(jar).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()

        /* TODO: reevaliuate after rebase
        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
         */
        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(responseMode = OpenIdConstants.ResponseModes.DIRECT_POST)
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Post>()
            .also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)

        /* TODO: reevaluate after rebase
        val validationResults = verifierSiop.validateAuthnResponseFromPost(authnResponse.content)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
         */
        val result =
            verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with direct_post_jwt" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(responseMode = OpenIdConstants.ResponseModes.DIRECT_POST_JWT)
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Post>()
            .also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)
        authnResponse.params.shouldHaveSize(1)
        val jarmResponse = authnResponse.params.values.first()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jarmResponse)!!).shouldBeTrue()

        /* TODO: reevaluate after rebase
        val validationResults = verifierSiop.validateAuthnResponseFromPost(authnResponse.content)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
         */
        val result =
            verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(
                responseMode = OpenIdConstants.ResponseModes.QUERY,
                state = expectedState
            )
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        /* TODO: reevaluate after rebase
        val validationResults = verifierSiop.validateAuthnResponse(authnResponse.url)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
         */
        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.state.shouldBe(expectedState)
    }

    "test with deserializing" {
        val authnRequest = verifierSiop.createAuthnRequest()
        val authnRequestUrlParams =
            authnRequest.encodeToParameters().formUrlEncode().also { println(it) }

        val parsedAuthnRequest: AuthenticationRequestParameters =
            authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderSiop.createAuthnResponseParams(parsedAuthnRequest).getOrThrow()
        val authnResponseParams =
            authnResponse.encodeToParameters().formUrlEncode().also { println(it) }

        val parsedAuthnResponse: AuthenticationResponseParameters =
            authnResponseParams.decodeFromPostBody()
        /* TODO: reevaluate after rebase
        val validationResults = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        validationResults.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.VerifiablePresentationValidationResults>()
        val result = validationResults.validationResults.first()
         */
        val result = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object" {
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow().also { println(it) }

        val authnResponse =
            holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object and Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService()
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierCryptoService)
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            attestationJwt = attestationJwt
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow().also { println(it) }


        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectJwsVerifier = verifierAttestationVerifier(sprsCryptoService.jsonWebKey)
        )
        val authnResponse =
            holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object and invalid Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService()
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierCryptoService)

        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            attestationJwt = attestationJwt
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow().also { println(it) }

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectJwsVerifier = verifierAttestationVerifier(DefaultCryptoService().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).also { println(it) }

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${Random.nextBytes(32).encodeToString(Base64UrlStrict)}"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) authnRequest else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri as JWS" {
        val jar = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow().also { println(it.serialize()) }

        val requestUrl = "https://www.example.com/request/${Random.nextBytes(32).encodeToString(Base64UrlStrict)}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object not verified" {
        val jar = verifierSiop.createAuthnRequestAsSignedRequestObject(
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow().also { println(it.serialize()) }

        val requestUrl = "https://www.example.com/request/${Random.nextBytes(32).encodeToString(Base64UrlStrict)}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            },
            requestObjectJwsVerifier = { _, _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }

    "test support for format holder specification" - {
        "test support for mso credential request" - {
            "if available despite others" {
                runBlocking {
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
            "if not available despite others" {
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
        }
        "test support for sd jwt credential request" - {
            "if available despite others" {
                runBlocking {
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
            }
            "if not available despite others" {
                runBlocking {
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
        }

        "test support for plain jwt credential request" - {
            "if available despite others" {
                runBlocking {
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
                    credentialScheme = ConstantIndex.MobileDrivingLicence2023
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
            "if not available despite others" {
                runBlocking {
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
    }


    "test support presentation of multiple credentials" {
        runBlocking {
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
        )
        val authnRequest2 = verifierSiop.createAuthnRequest(
            credentialScheme = ConstantIndex.MobileDrivingLicence2023,
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
        )
        val inputDescriptors2 = authnRequest2.presentationDefinition?.inputDescriptors ?: listOf()

        val authnRequest = authnRequest1.copy(
            presentationDefinition = authnRequest1.presentationDefinition?.let { presentationDefinition ->
                presentationDefinition.copy(
                    inputDescriptors = presentationDefinition.inputDescriptors + inputDescriptors2,
                    formats = FormatHolder(
                        jwt = presentationDefinition.formats?.jwt ?: authnRequest2.presentationDefinition?.formats?.jwt,
                        jwtVc = presentationDefinition.formats?.jwtVc ?: authnRequest2.presentationDefinition?.formats?.jwtVc,
                        jwtVp = presentationDefinition.formats?.jwtVp ?: authnRequest2.presentationDefinition?.formats?.jwtVp,
                        jwtSd = presentationDefinition.formats?.jwtSd ?: authnRequest2.presentationDefinition?.formats?.jwtSd,
                        msoMdoc = presentationDefinition.formats?.msoMdoc ?: authnRequest2.presentationDefinition?.formats?.msoMdoc,
                    )
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

private suspend fun buildAttestationJwt(
    sprsCryptoService: DefaultCryptoService,
    relyingPartyUrl: String,
    verifierCryptoService: CryptoService
): JwsSigned = DefaultJwsService(sprsCryptoService).createSignedJws(
    header = JwsHeader(
        algorithm = sprsCryptoService.algorithm.toJwsAlgorithm(),
    ),
    payload = JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = relyingPartyUrl,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationKey = verifierCryptoService.jsonWebKey,
    ).serialize().encodeToByteArray()
).getOrThrow()

private fun verifierAttestationVerifier(trustedKey: JsonWebKey) =
    object : RequestObjectJwsVerifier {
        override fun invoke(jws: JwsSigned, authnRequest: AuthenticationRequestParameters): Boolean {
            val attestationJwt = jws.header.attestationJwt?.let { JwsSigned.parse(it) }
                ?: return false
            val verifierJwsService = DefaultVerifierJwsService()
            if (!verifierJwsService.verifyJws(attestationJwt, trustedKey))
                return false
            val verifierPublicKey = JsonWebToken.deserialize(attestationJwt.payload.decodeToString())
                .getOrNull()?.confirmationKey ?: return false
            return verifierJwsService.verifyJws(jws, verifierPublicKey)
        }
    }

private suspend fun verifySecondProtocolRun(
    verifierSiop: OidcSiopVerifier,
    walletUrl: String,
    holderSiop: OidcSiopWallet
) {
    val authnRequestUrl = verifierSiop.createAuthnRequestUrl(walletUrl = walletUrl)
    val authnResponse = holderSiop.createAuthnResponse(authnRequestUrl)
    val validation = verifierSiop.validateAuthnResponse(
        (authnResponse.getOrThrow() as OidcSiopWallet.AuthenticationResponseResult.Redirect).url
    )
    validation.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
}