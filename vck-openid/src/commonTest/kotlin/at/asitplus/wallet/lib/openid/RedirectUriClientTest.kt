package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val RedirectUriClientTest by testSuite {

    withFixtureGenerator(suspend {
        val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent: Holder = HolderAgent(holderKeyMaterial).also { agent ->
            agent.storeCredential(
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

            val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val clientId: String = "https://example.com/rp/${uuid4()}"
            val walletUrl: String = "https://example.com/wallet/${uuid4()}"

            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            )
        }
    }) - {

        "test with Fragment" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                defaultRequestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldNotContain("?")
            authnResponse.url.shouldContain("#")
            authnResponse.url.shouldStartWith(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()

            verifySecondProtocolRun(it.verifierOid4vp, it.walletUrl, it.holderOid4vp)
        }

        "wrong client nonce in id_token should lead to error" {
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                nonceService = object : NonceService {
                    override suspend fun provideNonce() = uuid4().toString()
                    override suspend fun verifyNonce(it: String) = false
                    override suspend fun verifyAndRemoveNonce(it: String) = false
                }
            )
            val requestOptions = OpenId4VpRequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseType = OpenIdConstants.ID_TOKEN
            )
            val authnRequest = verifierOid4vp.createAuthnRequest(
                requestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
                .field shouldBe "idToken"
        }

        "wrong client nonce in vp_token should lead to error" {
            val verifierOid4vp = OpenId4VpVerifier(
                keyMaterial = it.verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(it.clientId),
                stateToAuthnRequestStore = object : MapStore<String, AuthenticationRequestParameters> {
                    override suspend fun put(key: String, value: AuthenticationRequestParameters) {}
                    override suspend fun get(key: String): AuthenticationRequestParameters? = null
                    override suspend fun remove(key: String): AuthenticationRequestParameters? = null
                },
            )
            val authnRequest = verifierOid4vp.createAuthnRequest(
                defaultRequestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.ValidationError>()
                .field shouldBe "input"
        }

        "signed requests not allowed for redirect-uri" {
            shouldThrow<IllegalArgumentException> {
                it.verifierOid4vp.createAuthnRequest(
                    defaultRequestOptions, CreationOptions.SignedRequestByValue(it.walletUrl)
                ).getOrThrow().url
            }
        }

        "signed request by reference not allowed for redirect-uri" {
            shouldThrow<IllegalArgumentException> {
                it.verifierOid4vp.createAuthnRequest(
                    defaultRequestOptions,
                    CreationOptions.SignedRequestByReference(it.walletUrl, "https://example.com")
                ).getOrThrow().url
            }
        }

        "test with direct_post" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = it.clientId,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            authnResponse.url.shouldBe(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post.jwt" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.clientId,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    url.shouldBe(it.clientId)
                    params.shouldHaveSize(1) // only the "response" object
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode())
                .shouldBeInstanceOf<AuthnResponseResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with Query" {
            val expectedState = uuid4().toString()
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    responseMode = OpenIdConstants.ResponseMode.Query,
                    state = expectedState
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldContain("?")
            authnResponse.url.shouldNotContain("#")
            authnResponse.url.shouldStartWith(it.clientId)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .shouldBeInstanceOf<AuthnResponseResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty()
                }
        }

        "test with deserializing" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(defaultRequestOptions)
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
                CreationOptions.Query(it.walletUrl)
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
    }
}

private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ),
)

private suspend fun verifySecondProtocolRun(
    verifierOid4vp: OpenId4VpVerifier,
    walletUrl: String,
    holderOid4vp: OpenId4VpHolder,
) {
    val authnRequestUrl = verifierOid4vp.createAuthnRequest(
        defaultRequestOptions, CreationOptions.Query(walletUrl)
    ).getOrThrow().url
    val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl)
    verifierOid4vp.validateAuthnResponse((authnResponse.getOrThrow() as AuthenticationResponseResult.Redirect).url)
        .shouldBeInstanceOf<AuthnResponseResult.Success>()
}

private val defaultRequestOptions = OpenId4VpRequestOptions(
    credentials = setOf(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    )
)
