package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
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

class PreRegisteredClientTest : FreeSpec({

    lateinit var clientId: String
    lateinit var walletUrl: String
    lateinit var redirectUrl: String
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierKeyMaterial: KeyMaterial
    lateinit var holderAgent: Holder
    lateinit var holderOid4vp: OpenId4VpHolder
    lateinit var verifierOid4vp: OpenId4VpVerifier
    lateinit var defaultRequestOptions: RequestOptions
    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierKeyMaterial = EphemeralKeyWithoutCert()
        clientId = "PRE-REGISTERED-CLIENT"
        redirectUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        holderAgent = HolderAgent(holderKeyMaterial)

        holderAgent.storeCredential(
            IssuerAgent(identifier = "https://issuer.example.com/".toUri())
                .issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
        )

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
        )
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
        )
        defaultRequestOptions = RequestOptions(
            credentials = setOf(
                RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
            ),
        )
    }

    "test with Fragment" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.Fragment,
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldNotContain("?")
        authnResponse.url.shouldContain("#")
        authnResponse.url.shouldStartWith(redirectUrl)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()

        verifierOid4vp.createAuthnRequest(
            defaultRequestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url.let { newAuthnRequestUrl ->
            verifySecondProtocolRun(
                verifierOid4vp, newAuthnRequestUrl, holderOid4vp
            )
        }
    }

    "test with Query" {
        val expectedState = uuid4().toString()
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.Query,
                state = expectedState,
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        authnResponse.url.shouldContain("?")
        authnResponse.url.shouldNotContain("#")
        authnResponse.url.shouldStartWith(redirectUrl)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.state.shouldBe(expectedState)
    }

    "wrong client nonce in id_token should lead to error" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
            nonceService = object : NonceService {
                override suspend fun provideNonce() = uuid4().toString()
                override suspend fun verifyNonce(it: String) = false
                override suspend fun verifyAndRemoveNonce(it: String) = false
            }
        )
        val requestOptions = RequestOptions(
            credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
            responseType = OpenIdConstants.ID_TOKEN,
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        result.field shouldBe "idToken"
    }

    "wrong client nonce in vp_token should lead to error" {
        verifierOid4vp = OpenId4VpVerifier(
            keyMaterial = verifierKeyMaterial,
            clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
            stateToAuthnRequestStore = object : MapStore<String, AuthenticationRequestParameters> {
                override suspend fun put(key: String, value: AuthenticationRequestParameters) {}
                override suspend fun get(key: String): AuthenticationRequestParameters? = null
                override suspend fun remove(key: String): AuthenticationRequestParameters? = null
            },
        )
        val authnRequest = verifierOid4vp.createAuthnRequest(
            defaultRequestOptions, OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
        result.shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
        result.field shouldBe "state"
    }

    "test with QR Code" {
        val authnRequestUrl = verifierOid4vp.createAuthnRequest(
            defaultRequestOptions, OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
        ).getOrThrow().url
        val authnRequest: JarRequestParameters =
            Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
        authnRequest.clientId shouldBe clientId
        val jar = authnRequest.request
            .shouldNotBeNull()
        val jwsObject = JwsSigned.Companion.deserialize<AuthenticationRequestParameters>(
            AuthenticationRequestParameters.Companion.serializer(), jar,
            vckJsonSerializer
        ).getOrThrow()
        VerifyJwsObject().invoke(jwsObject).shouldBeTrue()

        val authnResponse = holderOid4vp.createAuthnResponse(jar).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
    }

    "test with direct_post" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = redirectUrl
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
        authnResponse.url.shouldBe(redirectUrl)

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
    }

    "test with direct_post_jwt" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            RequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = redirectUrl
            ),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                url.shouldBe(redirectUrl)
                params.shouldHaveSize(1) // only the "response" object
            }
        val jarmResponse = authnResponse.params.entries.first { it.key == "response" }.value
        val jwsObject = JwsSigned.Companion.deserialize<AuthenticationResponseParameters>(
            AuthenticationResponseParameters.Companion.serializer(), jarmResponse
        ).getOrThrow()
        VerifyJwsObject().invoke(jwsObject).shouldBeTrue()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
    }

    "test with deserializing" {
        val authnRequest = verifierOid4vp.createAuthnRequest(defaultRequestOptions)
        val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()

        val parsedAuthnRequest: AuthenticationRequestParameters =
            authnRequestUrlParams.decodeFromUrlQuery()
        val authnResponse = holderOid4vp.createAuthnResponseParams(
            RequestParametersFrom.Uri<AuthenticationRequestParameters>(
                Url(authnRequestUrlParams),
                parsedAuthnRequest
            )
        ).getOrThrow().params
        val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

        val result = verifierOid4vp.validateAuthnResponse(authnResponseParams)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
    }

    "test specific credential" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.vp.freshVerifiableCredentials.map { it.vcJws }.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object" {
        val authnRequestWithRequestObject = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(walletUrl)
        ).getOrThrow().url

        val authnResponse = holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.vp.freshVerifiableCredentials.map { it.vcJws }.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri as URL query parameters" {
        val authnRequest = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(),
            OpenId4VpVerifier.CreationOptions.Query(walletUrl)
        ).getOrThrow().url

        val clientId = Url(authnRequest).parameters["client_id"]!!
        val requestUrl = "https://www.example.com/request/${uuid4()}"

        val authRequestUrlWithRequestUri = URLBuilder(walletUrl).apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", requestUrl)
        }.buildString()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) authnRequest else null
            }
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.vp.freshVerifiableCredentials.map { it.vcJws }.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri as JWS" {
        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val (authRequestUrlWithRequestUri, jar) = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(),
            OpenId4VpVerifier.CreationOptions.SignedRequestByReference(walletUrl, requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            }
        )

        val authnResponse = holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        val result = verifierOid4vp.validateAuthnResponse(authnResponse.url)
            .shouldBeInstanceOf<AuthnResponseResult.Success>()
        result.vp.freshVerifiableCredentials.shouldNotBeEmpty()
        result.vp.freshVerifiableCredentials.map { it.vcJws }.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
        }
    }

    "test with request object from request_uri contains wallet_nonce, but not in store should fail" {
        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val (authRequestUrlWithRequestUri, jar) = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(),
            OpenId4VpVerifier.CreationOptions.RequestByReference(walletUrl, requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        val nonceMap = mutableMapOf<String, String>()
        val walletNonceMapStore = object : MapStore<String, String> {
            override suspend fun put(key: String, value: String) {
                nonceMap[key] = value.reversed()
            }

            override suspend fun get(key: String): String? = nonceMap[key]
            override suspend fun remove(key: String): String? = nonceMap.remove(key)
        }
        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) {
                    jar.invoke(it.requestObjectParameters).getOrThrow().also {
                        joseCompliantSerializer.decodeFromString<AuthenticationRequestParameters>(it).walletNonce.also {
                            it.shouldNotBeNull()
                            nonceMap.contains(it).shouldBeTrue()
                        }
                    }
                } else null
            },
            walletNonceMapStore = walletNonceMapStore
        )

        shouldThrow<OAuth2Exception> {
            holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }

    "test with request object not verified" {
        val requestUrl = "https://www.example.com/request/${uuid4()}"
        val (authRequestUrlWithRequestUri, jar) = verifierOid4vp.createAuthnRequest(
            requestOptionsAtomicAttribute(),
            OpenId4VpVerifier.CreationOptions.SignedRequestByReference(walletUrl, requestUrl)
        ).getOrThrow()
        jar.shouldNotBeNull()

        holderOid4vp = OpenId4VpHolder(
            holder = holderAgent,
            remoteResourceRetriever = {
                if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
            },
            requestObjectJwsVerifier = { _ -> false }
        )

        shouldThrow<OAuth2Exception> {
            holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
        }
    }
})

private fun requestOptionsAtomicAttribute() = RequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ),
)

private suspend fun verifySecondProtocolRun(
    verifierOid4vp: OpenId4VpVerifier,
    authnRequestUrl: String,
    holderOid4vp: OpenId4VpHolder,
) {
    val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl)
    verifierOid4vp.validateAuthnResponse((authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url)
        .shouldBeInstanceOf<AuthnResponseResult.Success>()
}
