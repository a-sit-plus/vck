package at.asitplus.wallet.lib.oidc

import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.RequestOptions
import at.asitplus.wallet.lib.oidvci.*
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
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds

@Suppress("unused")
class OidcSiopProtocolTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var responseUrl: String
    lateinit var walletUrl: String

    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var verifierKeyPair: KeyPairAdapter

    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderKeyPair = RandomKeyPairAdapter()
        verifierKeyPair = RandomKeyPairAdapter()
        val rpUUID = uuid4()
        relyingPartyUrl = "https://example.com/rp/$rpUUID"
        responseUrl = "https://example.com/rp/$rpUUID"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyPair)
        verifierAgent = VerifierAgent(verifierKeyPair)

        holderAgent.storeCredential(
            IssuerAgent(
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
        )
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
        )
    }

    "test with Fragment" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl = walletUrl)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(relyingPartyUrl)

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()

        verifySecondProtocolRun(verifierSiop, walletUrl, holderSiop)
    }

    "wrong client nonce should lead to error" {
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
            nonceService = object : NonceService {
                override suspend fun provideNonce(): String {
                    return uuid4().toString()
                }

                override suspend fun verifyNonce(it: String): Boolean {
                    return false
                }

                override suspend fun verifyAndRemoveNonce(it: String): Boolean {
                    return false
                }
            }
        )
        val authnRequest = verifierSiop.createAuthnRequestUrl(walletUrl = walletUrl)

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.ValidationError>()
        result.field shouldBe "nonce"
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
        DefaultVerifierJwsService().verifyJwsObject(metadataObject).shouldBeTrue()

        val authnRequestUrl =
            verifierSiop.createAuthnRequestUrlWithRequestObject(walletUrl).getOrThrow()
        val authnRequest: AuthenticationRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe relyingPartyUrl
        val jar = authnRequest.request
        jar.shouldNotBeNull()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jar).getOrThrow()).shouldBeTrue()

        val authnResponse = holderSiop.createAuthnResponse(jar).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(responseMode = OpenIdConstants.ResponseMode.DIRECT_POST)
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
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
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(relyingPartyUrl)
        authnResponse.params.shouldHaveSize(1)
        val jarmResponse = authnResponse.params.values.first()
        DefaultVerifierJwsService().verifyJwsObject(JwsSigned.parse(jarmResponse).getOrThrow()).shouldBeTrue()

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
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

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
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()

        val parsedAuthnRequest: AuthenticationRequestParameters =
            authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderSiop.createAuthnResponseParams(
            AuthenticationRequestParametersFrom.Uri(
                Url(authnRequestUrlParams),
                parsedAuthnRequest
            )
        ).getOrThrow().params
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

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
        )

        val authnResponse = holderSiop.createAuthnResponse(authnRequest).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

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
        ).getOrThrow()

        val authnResponse = holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object and Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(RandomKeyPairAdapter())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierKeyPair)
        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
            attestationJwt = attestationJwt
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
            requestObjectJwsVerifier = verifierAttestationVerifier(sprsCryptoService.keyPairAdapter.jsonWebKey)
        )
        val authnResponse = holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierSiop.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
        result.vp.verifiableCredentials.shouldNotBeEmpty()
        result.vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }
    "test with request object and invalid Attestation JWT" {
        val sprsCryptoService = DefaultCryptoService(RandomKeyPairAdapter())
        val attestationJwt = buildAttestationJwt(sprsCryptoService, relyingPartyUrl, verifierKeyPair)

        verifierSiop = OidcSiopVerifier.newInstance(
            verifier = verifierAgent,
            relyingPartyUrl = relyingPartyUrl,
            attestationJwt = attestationJwt
        )
        val authnRequestWithRequestObject = verifierSiop.createAuthnRequestUrlWithRequestObject(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        ).getOrThrow()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
            requestObjectJwsVerifier = verifierAttestationVerifier(RandomKeyPairAdapter().jsonWebKey)
        )
        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierSiop.createAuthnRequestUrl(
            walletUrl = walletUrl,
            requestOptions = RequestOptions(credentialScheme = ConstantIndex.AtomicAttribute2023)
        )

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${uuid4()}"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) authnRequest else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

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
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            }
        )

        val authnResponse = holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        authnResponse.shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

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
        ).getOrThrow()

        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", relyingPartyUrl)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderSiop = OidcSiopWallet.newDefaultInstance(
            keyPairAdapter = holderKeyPair,
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it == requestUrl) jar.serialize() else null
            },
            requestObjectJwsVerifier = { _, _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderSiop.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }
})

private suspend fun buildAttestationJwt(
    sprsCryptoService: DefaultCryptoService,
    relyingPartyUrl: String,
    verifierKeyPair: KeyPairAdapter
): JwsSigned = DefaultJwsService(sprsCryptoService).createSignedJws(
    header = JwsHeader(
        algorithm = sprsCryptoService.keyPairAdapter.signingAlgorithm.toJwsAlgorithm().getOrThrow(),
    ),
    payload = JsonWebToken(
        issuer = "sprs", // allows Wallet to determine the issuer's key
        subject = relyingPartyUrl,
        issuedAt = Clock.System.now(),
        expiration = Clock.System.now().plus(10.seconds),
        notBefore = Clock.System.now(),
        confirmationKey = verifierKeyPair.jsonWebKey,
    ).serialize().encodeToByteArray()
).getOrThrow()

private fun verifierAttestationVerifier(trustedKey: JsonWebKey) =
    object : RequestObjectJwsVerifier {
        override fun invoke(jws: JwsSigned, authnRequest: AuthenticationRequestParameters): Boolean {
            val attestationJwt = jws.header.attestationJwt?.let { JwsSigned.parse(it).getOrThrow() }
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
        (authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url
    )
    validation.shouldBeInstanceOf<OidcSiopVerifier.AuthnResponseResult.Success>()
}