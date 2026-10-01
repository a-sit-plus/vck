package at.asitplus.wallet.lib.oidvci

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

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseEncryption
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SupportedAlgorithmsContainer
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonElement

val OidvciEncryptionTest by matrixSuite {

    fixture {
        object {
            val authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = CredentialAuthorizationServiceStrategy(setOf(ConstantIndex.AtomicAttribute2023)),
            )
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true, // this is important
                    decryptionKeyMaterial = EphemeralKeyWithoutCert()
                ),
            )
            val state = uuid4().toString()
            val client = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true, // this is important
                    requireRequestEncryption = true, // this is important
                )
            )
            val oauth2Client = OAuth2Client()
            suspend fun getToken(scope: String): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                val input = authnRequest as RequestParameters
                val authnResponse = authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                    .getOrThrow()
                    .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                val code = authnResponse.params?.code
                    .shouldNotBeNull()
                val tokenRequest = oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

        }
    } - {
        test("wallet encrypts credential request and decrypts credential response") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
                .shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>()
            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().apply {
                this.shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>()
                it.client.parseCredentialResponse(this, request, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                        signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
                            .also { credentialSubject ->
                                shouldNotThrowAny {
                                    AtomicAttribute2023.fromJsonElement(credentialSubject)
                                }
                            }
                    }
            }
        }

        /**
         * OID4VCI: *"Credential Request encryption MUST be used if the `credential_response_encryption` parameter is
         * included, to prevent it being substituted by an attacker"*, so the wallet must not hand out its response
         * encryption key in a request it is unable to encrypt.
         */
        test("wallet refuses to request response encryption when it can't encrypt the request") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                it.client.createCredential(
                    tokenResponse = token,
                    // the issuer requires response encryption, but publishes no key to encrypt the request to
                    metadata = it.issuer.metadata.copy(credentialRequestEncryption = null),
                    credentialFormat = credentialFormat,
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow()
            }
        }

        test("wallet does not encrypt credential request but issuer requires this") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true,
                    decryptionKeyMaterial = EphemeralKeyWithoutCert(),
                    requireRequestEncryption = true, // this is important for this test
                ),
            )

            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            val request = it.client.createCredential(
                tokenResponse = token,
                // trick wallet into not encrypting, and into not asking for an encrypted response either
                metadata = it.issuer.metadata.copy(
                    credentialRequestEncryption = null,
                    credentialResponseEncryption = null,
                ),
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
                .shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()

            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }

        }

        /**
         * The regression test for the rule above: nothing is *required* here, the wallet merely asks for an encrypted
         * response, which alone makes request encryption mandatory.
         */
        test("wallet encrypts the request because it asks for an encrypted response") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(), // requires nothing, but supports both
            )
            val client = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true, // this is important
                    requireRequestEncryption = false, // this is important
                )
            )
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())

            val request = client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
                .shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>()
            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().apply {
                shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>()
                client.parseCredentialResponse(this, request, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>()
            }
        }

        test("wallet wanting no encryption sends a plain request without response encryption parameters") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(), // requires nothing, but supports both
            )
            val client = WalletService() // wants nothing
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().shouldBeSingleton().first()
                    .shouldBeInstanceOf<WalletService.CredentialRequest.Plain>().apply {
                        request.credentialResponseEncryption.shouldBeNull()
                    },
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
        }

        test("issuer rejects response encryption parameters sent in a plain request") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(), // requires nothing, but supports both
            )
            val client = WalletService() // wants nothing, so it creates a plain request for us to tamper with
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())
            val plainRequest = client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
                .shouldBeInstanceOf<WalletService.CredentialRequest.Plain>()

            // a non-conforming wallet, whose key an attacker could substitute on the way
            val tampered = WalletService.CredentialRequest.Plain(
                plainRequest.request.copy(
                    credentialResponseEncryption = CredentialResponseEncryption(
                        jsonWebKey = EphemeralKeyWithoutCert().jsonWebKey,
                        jweAlgorithm = JweAlgorithm.ECDH_ES,
                        jweEncryption = JweEncryption.A256GCM,
                    )
                )
            )

            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = tampered,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        test("every credential request carries its own response encryption key") {
            val encryptionService = WalletEncryptionService(requestResponseEncryption = true)

            val first = encryptionService.credentialResponseEncryption(it.issuer.metadata).shouldNotBeNull()
            val second = encryptionService.credentialResponseEncryption(it.issuer.metadata).shouldNotBeNull()

            first.jsonWebKey.keyId.shouldNotBeNull() shouldNotBe second.jsonWebKey.keyId.shouldNotBeNull()
            first.jsonWebKey shouldNotBe second.jsonWebKey
        }

        test("a response encrypted to a key we never announced is not decryptable") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
            val response = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>()

            // the wallet that made the request holds the matching key, identified by the JWE `kid`
            response.response.header.keyId.shouldNotBeNull()
            it.client.parseCredentialResponse(response, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                .isFailure shouldBe true
            it.client.parseCredentialResponse(response, request, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                .getOrThrow()
            // another wallet, which never announced that key, must not be able to read the credential
            WalletService(encryptionService = WalletEncryptionService(requestResponseEncryption = true))
                .parseCredentialResponse(response, request, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                .isFailure shouldBe true
        }

        test("an encrypted response is bound to its credential request and accepted only once") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())
            suspend fun createRequest() = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
            suspend fun createResponse(request: WalletService.CredentialRequest) = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>()

            val firstRequest = createRequest()
            val secondRequest = createRequest()
            val firstResponse = createResponse(firstRequest)
            val secondResponse = createResponse(secondRequest)

            it.client.parseCredentialResponse(
                secondResponse, firstRequest, PLAIN_JWT, ConstantIndex.AtomicAttribute2023
            ).isFailure shouldBe true
            it.client.parseCredentialResponse(
                firstResponse, firstRequest, PLAIN_JWT, ConstantIndex.AtomicAttribute2023
            ).getOrThrow()
            it.client.parseCredentialResponse(
                secondResponse, secondRequest, PLAIN_JWT, ConstantIndex.AtomicAttribute2023
            ).getOrThrow()
            it.client.parseCredentialResponse(
                secondResponse, secondRequest, PLAIN_JWT, ConstantIndex.AtomicAttribute2023
            ).isFailure shouldBe true
        }

        test("another wallet instance can decrypt through a shared ephemeral key store") {
            val keyStore = DefaultMapStore<String, String>()
            val requestClient = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true,
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(keyStore),
                )
            )
            val responseClient = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true,
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(keyStore),
                )
            )
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = requestClient.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(credentialFormat.scope.shouldNotBeNull())
            val request = requestClient.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
            val response = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = request,
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()

            responseClient.parseCredentialResponse(
                response, request, PLAIN_JWT, ConstantIndex.AtomicAttribute2023
            ).getOrThrow()
        }

        test("wallet omits optional response encryption when no algorithm is shared") {
            val unsupported = it.issuer.metadata.copy(
                credentialResponseEncryption = SupportedAlgorithmsContainer(
                    supportedAlgorithmsStrings = setOf("unsupported"),
                    supportedEncryptionAlgorithmsStrings = setOf(JweEncryption.A256GCM.identifier),
                    encryptionRequired = false,
                )
            )
            WalletEncryptionService(requestResponseEncryption = true)
                .credentialResponseEncryption(unsupported).shouldBeNull()

            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                WalletEncryptionService(requestResponseEncryption = true).credentialResponseEncryption(
                    unsupported.copy(
                        credentialResponseEncryption = unsupported.credentialResponseEncryption?.copy(
                            encryptionRequired = true
                        )
                    )
                )
            }
        }

        test("issuer rejects response algorithms it did not advertise") {
            val responseEncryption = WalletEncryptionService(requestResponseEncryption = true)
                .credentialResponseEncryption(it.issuer.metadata).shouldNotBeNull()
            val request = CredentialRequestParameters(credentialResponseEncryption = responseEncryption)

            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                IssuerEncryptionService(supportedJweAlgorithms = emptySet()).encryptResponse(
                    CredentialResponseParameters(), request
                )
            }
            shouldThrow<OAuth2Exception.InvalidEncryptionParameters> {
                IssuerEncryptionService(supportedJweEncryptionAlgorithms = emptySet()).encryptResponse(
                    CredentialResponseParameters(), request
                )
            }
        }

        test("issuer fails to encrypt response") {
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(ConstantIndex.AtomicAttribute2023),
                encryptionService = IssuerEncryptionService(
                    requireResponseEncryption = true,
                    encryptCredentialResponse = EncryptJweFun { _, _, _ ->
                        KmmResult.catching { TODO("issuer fails to encrypt") }
                    }
                ),
            )
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat =
                it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                    .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            val request = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()
                .shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>()

            shouldThrowAny {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = request,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }
    }

}
