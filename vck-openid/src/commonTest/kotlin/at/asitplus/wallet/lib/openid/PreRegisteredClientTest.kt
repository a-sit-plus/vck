package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
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

val PreRegisteredClientTest by testSuite {

    withFixtureGenerator(suspend {
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent = HolderAgent(holderKeyMaterial).also {
            it.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {
            val holderAgent = holderAgent
            val verifierKeyMaterial = EphemeralKeyWithoutCert()
            val decryptionKeyMaterial = EphemeralKeyWithoutCert()
            val clientId = "PRE-REGISTERED-CLIENT-${uuid4()}"
            val redirectUrl = "https://example.com/rp/${uuid4()}"
            val walletUrl = "https://example.com/wallet/${uuid4()}"

            var holderOid4vp = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
                lookupJsonWebKeysForClient = {
                    if (it.clientId == clientId) JsonWebKeySet(listOf(decryptionKeyMaterial.jsonWebKey)) else null
                }
            )
            var verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
                decryptionKeyMaterial = decryptionKeyMaterial
            )
            val defaultRequestOptions = OpenId4VpRequestOptions(
                credentials = setOf(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                ),
            )
        }
    }) - {

        "test with Fragment" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.Fragment,
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldNotContain("?")
            authnResponse.url.shouldContain("#")
            authnResponse.url.shouldStartWith(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()

            it.verifierOid4vp.createAuthnRequest(
                it.defaultRequestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url.let { newAuthnRequestUrl ->
                verifySecondProtocolRun(
                    it.verifierOid4vp, newAuthnRequestUrl, it.holderOid4vp
                )
            }
        }

        "test with Query" {
            val expectedState = uuid4().toString()
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.Query,
                    state = expectedState,
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldContain("?")
            authnResponse.url.shouldNotContain("#")
            authnResponse.url.shouldStartWith(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty()
                }
        }

        "wrong client nonce in id_token should lead to error" {
            it.verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.PreRegistered(it.clientId, it.redirectUrl),
                nonceService = object : NonceService {
                    override suspend fun provideNonce() = uuid4().toString()
                    override suspend fun verifyNonce(it: String) = false
                    override suspend fun verifyAndRemoveNonce(it: String) = false
                }
            )
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseType = OpenIdConstants.ID_TOKEN,
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
                .field shouldBe "idToken"
        }

        "wrong client nonce in vp_token should lead to error" {
            it.verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.PreRegistered(it.clientId, it.redirectUrl),
                stateToAuthnRequestStore = object : MapStore<String, AuthenticationRequestParameters> {
                    override suspend fun put(key: String, value: AuthenticationRequestParameters) {}
                    override suspend fun get(key: String): AuthenticationRequestParameters? = null
                    override suspend fun remove(key: String): AuthenticationRequestParameters? = null
                },
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                it.defaultRequestOptions, OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
                .field shouldBe "input"
        }

        "test with QR Code" {
            val authnRequestUrl = it.verifierOid4vp.createAuthnRequest(
                it.defaultRequestOptions, OpenId4VpVerifier.CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url
            val authnRequest: JarRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            authnRequest.clientId shouldBe it.clientId
            val jar = authnRequest.request
                .shouldNotBeNull()
            val jwsObject = JwsSigned.deserialize(AuthenticationRequestParameters.serializer(), jar, vckJsonSerializer)
                .getOrThrow()
            VerifyJwsObject().invoke(jwsObject).getOrThrow()

            val authnResponse = it.holderOid4vp.createAuthnResponse(jar).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
        }

        "test with direct_post" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = it.redirectUrl
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            authnResponse.url.shouldBe(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post.jwt" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.redirectUrl
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    url.shouldBe(it.redirectUrl)
                    params.shouldHaveSize(1) // only the "response" object
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post.jwt, no key for client, leads to error" {
            it.holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                randomSource = RandomSource.Default,
                lookupJsonWebKeysForClient = { null } // provide no key for pre-registered client
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.redirectUrl
                ),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            shouldThrow<OAuth2Exception> {
                it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            }
        }

        "test with deserializing" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(it.defaultRequestOptions)
            val authnRequestUrlParams = authnRequest.encodeToParameters().formUrlEncode()

            val parsedAuthnRequest: AuthenticationRequestParameters =
                authnRequestUrlParams.decodeFromUrlQuery()
            val authnResponse = it.holderOid4vp.createAuthnResponse(
                RequestParametersFrom.Uri(
                    Url(authnRequestUrlParams),
                    parsedAuthnRequest
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params
            val authnResponseParams = authnResponse.encodeToParameters().formUrlEncode()

            it.verifierOid4vp.validateAuthnResponse(authnResponseParams)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test specific credential" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                OpenId4VpVerifier.CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
        }

        "test with request object" {
            val authnRequestWithRequestObject = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), OpenId4VpVerifier.CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
        }

        "test with request object from request_uri as JWS" {
            val requestUrl = "https://www.example.com/request/${uuid4()}"
            val (authRequestUrlWithRequestUri, jar) = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                OpenId4VpVerifier.CreationOptions.SignedRequestByReference(it.walletUrl, requestUrl)
            ).getOrThrow()
            jar.shouldNotBeNull()

            it.holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
                },
                randomSource = RandomSource.Default,
            )

            val authnResponse = it.holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
                }
        }

        "test with request object from request_uri contains wallet_nonce, but not in store should fail" {
            val requestUrl = "https://www.example.com/request/${uuid4()}"
            val (authRequestUrlWithRequestUri, jar) = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                OpenId4VpVerifier.CreationOptions.RequestByReference(it.walletUrl, requestUrl)
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
            it.holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
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
                walletNonceMapStore = walletNonceMapStore,
                randomSource = RandomSource.Default,
            )

            shouldThrow<OAuth2Exception.InvalidRequest> {
                it.holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            }
        }

        "test with request object not verified" {
            val requestUrl = "https://www.example.com/request/${uuid4()}"
            val (authRequestUrlWithRequestUri, jar) = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                OpenId4VpVerifier.CreationOptions.SignedRequestByReference(it.walletUrl, requestUrl)
            ).getOrThrow()
            jar.shouldNotBeNull()

            it.holderOid4vp = OpenId4VpHolder(
                holder = it.holderAgent,
                remoteResourceRetriever = {
                    if (it.url == requestUrl) jar.invoke(it.requestObjectParameters).getOrThrow() else null
                },
                requestObjectJwsVerifier = { _ -> false },
                randomSource = RandomSource.Default,
            )

            shouldThrow<OAuth2Exception> {
                it.holderOid4vp.createAuthnResponse(authRequestUrlWithRequestUri).getOrThrow()
            }
        }
    }
}

private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
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
        .getOrThrow()
        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    verifierOid4vp.validateAuthnResponse(authnResponse.url)
        .shouldBeInstanceOf<AuthnResponseResult.Success>()
}
