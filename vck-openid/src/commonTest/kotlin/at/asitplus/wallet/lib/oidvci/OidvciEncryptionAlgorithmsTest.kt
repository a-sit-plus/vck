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

import at.asitplus.catching
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

val OidvciEncryptionAlgorithmsTest by testSuite {

    withFixtureGenerator {
        object {
            val issuerEnc = JweEncryption.A128CBC_HS256
            val walletEnc = JweEncryption.A128GCM // will not be used, as wallet selects from issuer's algorithm!
            val authorizationService = SimpleAuthorizationService(
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
                    decryptionKeyMaterial = EphemeralKeyWithoutCert(),
                    supportedJweEncryptionAlgorithms = setOf(issuerEnc)
                ),
            )
            val state = uuid4().toString()
            val client = WalletService(
                encryptionService = WalletEncryptionService(
                    requestResponseEncryption = true, // this is important
                    requireRequestEncryption = true, // this is important
                    fallbackJweEncryptionAlgorithm = walletEnc
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

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().shouldBeSingleton().first()
                    .shouldBeInstanceOf<WalletService.CredentialRequest.Encrypted>().apply {
                        request.header.encryption shouldBe it.issuerEnc
                    },
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().apply {
                shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>().apply {
                    response.header.encryption shouldBe it.issuerEnc
                }
                it.client.parseCredentialResponse(this, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                        signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
                            .also { credentialSubject ->
                                shouldNotThrowAny {
                                    Json.decodeFromJsonElement(AtomicAttribute2023.serializer(), credentialSubject)
                                }
                            }
                    }
            }
        }

        test("wallet does not encrypt credential request and decrypts credential response") {
            val requestOptions = WalletService.RequestOptions(ConstantIndex.AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    // trick wallet into not encrypting
                    metadata = it.issuer.metadata.copy(credentialRequestEncryption = null),
                    credentialFormat = credentialFormat,
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().shouldBeSingleton().first()
                    .shouldBeInstanceOf<WalletService.CredentialRequest.Plain>().apply {
                        request.credentialResponseEncryption.shouldNotBeNull().apply {
                            jweEncryption shouldBe it.issuerEnc
                        }
                    },
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow().apply {
                shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Encrypted>().apply {
                    response.header.encryption shouldBe it.issuerEnc
                }
                it.client.parseCredentialResponse(this, PLAIN_JWT, ConstantIndex.AtomicAttribute2023)
                    .getOrThrow().first().shouldBeInstanceOf<Holder.StoreCredentialInput.Vc>().apply {
                        signedVcJws.payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
                            .also { credentialSubject ->
                                shouldNotThrowAny {
                                    Json.decodeFromJsonElement(AtomicAttribute2023.serializer(), credentialSubject)
                                }
                            }
                    }
            }
        }
    }

}