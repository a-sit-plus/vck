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
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
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
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.runBlocking

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

        val authnRequest = verifierSiop.createAuthnRequestAsRequestObject().getOrThrow()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jar)!!).shouldBeTrue()

        val authnResponse = holderSiop.createAuthnResponse(jar).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with POST" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            responseMode = OpenIdConstants.ResponseModes.POST
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Post>()
            .also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            responseMode = OpenIdConstants.ResponseModes.QUERY,
            state = expectedState
        ).also { println(it) }

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

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
        val result = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialScheme = ConstantIndex.AtomicAttribute2023
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

    "test with request object from request uri redirect" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialScheme = ConstantIndex.AtomicAttribute2023
        ).also { println(it) }

        val clientId =
            Url(authnRequest).parameters[AuthenticationRequestConstants.SerialNames.clientId].let {
                it shouldNotBe null
                it!!
            }

        val requestUrl = "http://www.example.com/requestUrl"
        val mockEngine = MockEngine { request ->
            if (request.url.toString() == requestUrl) {
                respondRedirect(authnRequest)
            } else {
                respondBadRequest()
            }
        }
        val httpClient = HttpClient(mockEngine) {
            followRedirects = false
        }

        val authRequestUrlWithRequestUri = URLBuilder("http://www.example.com/original").apply {
            parameters.append(AuthenticationRequestConstants.SerialNames.clientId, clientId)
            parameters.append(AuthenticationRequestConstants.SerialNames.requestUri, requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectCandidateRetriever = httpClient.asRequestObjectCandidateRetriever()
        )

        val authnResponse =
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request uri response body if it is a url" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            credentialScheme = ConstantIndex.AtomicAttribute2023
        ).also { println(it) }

        val clientId =
            Url(authnRequest).parameters[AuthenticationRequestConstants.SerialNames.clientId].let {
                it shouldNotBe null
                it!!
            }

        val requestUrl = "http://www.example.com/request"
        val mockEngine = MockEngine { request ->
            if (request.url.toString() == requestUrl) {
                respond(
                    content = ByteReadChannel(authnRequest),
                    status = HttpStatusCode.OK,
                )
            } else {
                respondBadRequest()
            }
        }
        val httpClient = HttpClient(mockEngine) {
            followRedirects = false
        }

        val authRequestUrlWithRequestUri = URLBuilder("http://www.example.com/original").apply {
            parameters.append(AuthenticationRequestConstants.SerialNames.clientId, clientId)
            parameters.append(AuthenticationRequestConstants.SerialNames.requestUri, requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectCandidateRetriever = httpClient.asRequestObjectCandidateRetriever()
        )

        val authnResponse =
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request uri response body if it is a jws" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
        )

        val authnRequest = verifierSiop.createAuthnRequest(
            credentialScheme = ConstantIndex.AtomicAttribute2023
        ).also { println(it) }

        val requestUrl = "http://www.example.com/request"
        val mockEngine = MockEngine { request ->
            if (request.url.toString() == requestUrl) {
                val authnRequestObjectJws =
                    DefaultJwsService(verifierCryptoService).createSignedJwsAddingParams(
                        payload = authnRequest.serialize().encodeToByteArray(),
                        addKeyId = true
                    ).getOrNull().let {
                        it shouldNotBe null
                        it!!
                    }

                respond(
                    content = ByteReadChannel(authnRequestObjectJws.serialize()),
                    status = HttpStatusCode.OK,
                )
            } else {
                respondBadRequest()
            }
        }
        val httpClient = HttpClient(mockEngine) {
            followRedirects = false
        }

        val authRequestUrlWithRequestUri = URLBuilder("http://www.example.com/original").apply {
            parameters.append(
                AuthenticationRequestConstants.SerialNames.clientId,
                authnRequest.clientId
            )
            parameters.append(AuthenticationRequestConstants.SerialNames.requestUri, requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectCandidateRetriever = httpClient.asRequestObjectCandidateRetriever()
        )

        val authnResponse =
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<OidcSiopWallet.AuthenticationResponseResult.Redirect>()
            .also { println(it) }

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
})

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

private fun HttpClient.asRequestObjectCandidateRetriever(): RequestObjectCandidateRetriever = {
    // currently supported in order of priority:
    // 1. use redirect location as new starting point if available
    // 2. use resonse body as new starting point
    val response = this.get(it)
    listOfNotNull(
        response.headers[HttpHeaders.Location],
        response.bodyAsText(),
    )
}