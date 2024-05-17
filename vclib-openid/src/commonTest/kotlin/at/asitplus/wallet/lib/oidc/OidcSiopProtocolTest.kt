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
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
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
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds

@Suppress("unused")
class OidcSiopProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var responseUrl: String
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
        val rpUUID = uuid4()
        relyingPartyUrl = "https://example.com/rp/$rpUUID"
        responseUrl = "https://example.com/rp/$rpUUID"
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

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            cryptoService = verifierCryptoService,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl = walletUrl)
            .also { println(it) }

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequest).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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

        val authnRequestUrl =
            verifierSiop.createAuthnRequestUrlWithRequestObject(walletUrl).getOrThrow()
        val authnRequest: AuthenticationRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jar).getOrThrow())
            .shouldBeTrue()

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(jar).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(responseMode = OpenIdConstants.ResponseMode.DIRECT_POST)
        ).also { println(it) }

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequest).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            .also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)

        val result =
            verifierSiop.validateAuthnResponseFromPost(authnResponse.params.formUrlEncode())
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test with direct_post_jwt" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(responseMode = OpenIdConstants.ResponseMode.DIRECT_POST_JWT)
        ).also { println(it) }

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequest).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            .also { println(it) }
        authnResponse.url.shouldBe(relyingPartyUrl)
        authnResponse.params.shouldHaveSize(1)
        val jarmResponse = authnResponse.params.values.first()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jarmResponse).getOrThrow())
            .shouldBeTrue()

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
                responseMode = OpenIdConstants.ResponseMode.QUERY,
                state = expectedState
            )
        ).also { println(it) }

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequest).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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
        // TODO: fix?
        val authnResponse = holderSiop.startAuthenticationResponsePreparation(
            AuthenticationRequestParametersFrom.Uri(
                Url(authnRequestUrlParams),
                parsedAuthnRequest
            )
        ).getOrThrow().let {
            holderSiop.finalizeAuthenticationResponseParameters(it)
        }.getOrThrow()
        val authnResponseParams =
            authnResponse.encodeToParameters().formUrlEncode().also { println(it) }

        val parsedAuthnResponse: AuthenticationResponseParameters =
            authnResponseParams.decodeFromPostBody()
        val result = verifierSiop.validateAuthnResponse(parsedAuthnResponse)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).also { println(it) }

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequest).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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
            holderSiop.startAuthenticationResponsePreparation(authnRequestWithRequestObject)
                .getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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
        val attestationJwt =
            buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierCryptoService)
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


        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectJwsVerifier = verifierAttestationVerifier(sprsCryptoService.jsonWebKey)
        )
        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authnRequestWithRequestObject).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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
        val attestationJwt =
            buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierCryptoService)

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

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            requestObjectJwsVerifier = verifierAttestationVerifier(DefaultCryptoService().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderSiop.startAuthenticationResponsePreparation(authnRequestWithRequestObject).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).also { println(it) }

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${
            Random.nextBytes(32).encodeToString(Base64UrlStrict)
        }"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) authnRequest else null
            }
        )

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authRequestUrlWithRequestUri).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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

        val requestUrl = "https://www.example.com/request/${
            Random.nextBytes(32).encodeToString(Base64UrlStrict)
        }"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            }
        )

        val authnResponse =
            holderSiop.startAuthenticationResponsePreparation(authRequestUrlWithRequestUri).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
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

        val requestUrl = "https://www.example.com/request/${
            Random.nextBytes(32).encodeToString(Base64UrlStrict)
        }"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            },
            requestObjectJwsVerifier = { _, _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderSiop.startAuthenticationResponsePreparation(authRequestUrlWithRequestUri).getOrThrow().let {
                holderSiop.finalizeAuthenticationResponseResult(it)
            }.getOrThrow()
        }
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
        override fun invoke(
            jws: JwsSigned,
            authnRequest: AuthenticationRequestParameters
        ): Boolean {
            val attestationJwt = jws.header.attestationJwt?.let { JwsSigned.parse(it).getOrThrow() }
                ?: return false
            val verifierJwsService = DefaultVerifierJwsService()
            if (!verifierJwsService.verifyJws(attestationJwt, trustedKey))
                return false
            val verifierPublicKey =
                JsonWebToken.deserialize(attestationJwt.payload.decodeToString())
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
    val authnResponse = holderSiop.startAuthenticationResponsePreparation(authnRequestUrl).getOrThrow().let {
        holderSiop.finalizeAuthenticationResponseResult(it)
    }.getOrThrow()
    authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    val validation = verifierSiop.validateAuthnResponse(authnResponse.url)
    validation.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
}