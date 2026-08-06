package at.asitplus.wallet.lib.openid

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.utils.MapStore
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement

val PreRegisteredClientTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                issueAndStorePlainJwt(it, holderKeyMaterial)
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
                    },
                )
                var verifierOid4vp = OpenId4VpVerifier(
                    keyMaterial = verifierKeyMaterial,
                    clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUrl),
                    decryptionKeyMaterial = decryptionKeyMaterial,
                )
                val defaultRequestOptions = OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                )
            }
        }
    } - {

        "test with Fragment" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.Fragment,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldNotContain("?")
            authnResponse.url.shouldContain("#")
            authnResponse.url.shouldStartWith(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()

            it.verifierOid4vp.createAuthnRequest(
                it.defaultRequestOptions, CreationOptions.Query(it.walletUrl)
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.Query,
                    state = expectedState,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            authnResponse.url.shouldContain("?")
            authnResponse.url.shouldNotContain("#")
            authnResponse.url.shouldStartWith(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>().apply {
                    vp.freshVerifiableCredentials.shouldNotBeEmpty()
                }
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
                it.defaultRequestOptions, CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).isFailure shouldBe true
        }

        "test with QR Code" {
            val authnRequestUrl = it.verifierOid4vp.createAuthnRequest(
                it.defaultRequestOptions, CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url
            val authnRequest: JarRequestParameters =
                Url(authnRequestUrl).encodedQuery.decodeFromUrlQuery()
            authnRequest.clientId shouldBe it.clientId
            val jar = authnRequest.request
                .shouldNotBeNull()
            val jwsObject = JwsCompactTyped<AuthenticationRequestParameters>(jar)
            VerifyJwsObject().invoke(jwsObject.jws).getOrThrow()

            val authnResponse = it.holderOid4vp.createAuthnResponse(jar).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        "test with direct_post" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = it.redirectUrl
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            authnResponse.url.shouldBe(it.redirectUrl)

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test with direct_post.jwt" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.redirectUrl
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>().apply {
                    url.shouldBe(it.redirectUrl)
                    params.shouldHaveSize(1) // only the "response" object
                }

            it.verifierOid4vp.validateAuthnResponse(authnResponse.params.formUrlEncode()).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
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
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                    ).toDCQLRequest(),
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = it.redirectUrl
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            shouldThrow<OAuth2Exception> {
                it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
            }
        }

        "test with deserializing" {
            val authnRequest = it.verifierOid4vp.createPlainAuthnRequest(it.defaultRequestOptions)
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

            it.verifierOid4vp.validateAuthnResponse(authnResponseParams).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
        }

        "test specific credential" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
                }
        }

        "test with request object" {
            val authnRequestWithRequestObject = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(), CreationOptions.SignedRequestByValue(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequestWithRequestObject).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
                }
        }

        "test with request object from request_uri as JWS" {
            val requestUrl = "https://www.example.com/request/${uuid4()}"
            val (authRequestUrlWithRequestUri, jar) = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                CreationOptions.SignedRequestByReference(it.walletUrl, requestUrl)
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

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
                .shouldBeSingleton().first()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .vp.freshVerifiableCredentials.shouldNotBeEmpty()
                .map { it.vcJws }.forEach {
                    it.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                        shouldNotThrowAny {
                            AtomicAttribute2023.fromJsonElement(credentialSubject)
                        }
                    }
                }
        }

        "test with request object from request_uri contains wallet_nonce, but not in store should fail" {
            val requestUrl = "https://www.example.com/request/${uuid4()}"
            val (authRequestUrlWithRequestUri, jar) = it.verifierOid4vp.createAuthnRequest(
                requestOptionsAtomicAttribute(),
                CreationOptions.RequestByReference(it.walletUrl, requestUrl)
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

        // "test with request object not verified" removed: it injected a RequestObjectJwsVerifier returning
        // false, which is no longer invoked. Rejecting a relying party is covered by OpenId4VpRelyingPartyTrustTest.
    }
}

private fun requestOptionsAtomicAttribute() = OpenId4VpRequestOptions(
    presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
    ).toDCQLRequest(),
)

private suspend fun verifySecondProtocolRun(
    verifierOid4vp: OpenId4VpVerifier,
    authnRequestUrl: String,
    holderOid4vp: OpenId4VpHolder,
) {
    val authnResponse = holderOid4vp.createAuthnResponse(authnRequestUrl)
        .getOrThrow()
        .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
    verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
        .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
        .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
        .credentialQueryResponseValidations.values.flatMap { it.map { it.getOrThrow() } }
        .shouldBeSingleton().first()
        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
}
