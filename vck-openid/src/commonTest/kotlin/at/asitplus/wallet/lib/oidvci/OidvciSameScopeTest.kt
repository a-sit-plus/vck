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
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oauth2.ValidatedAccessToken
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.JsonElement

val OidvciSameScopeTest by matrixSuite {

    fixture {
        object {
            val scope = uuid4().toString()
            val mapper = SameScopeCredentialSchemeMapper(scope)
            val authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = CredentialAuthorizationServiceStrategy(
                    credentialSchemes =  AttributeIndex.schemeSet,
                    mapper = mapper,
                ),
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes =  AttributeIndex.schemeSet,
                credentialSchemeMapper = mapper,
            )

            /** Behind the same AS, but all its configurations require a scope that is a substring of [scope]. */
            val substringScopeIssuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://other-issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                credentialSchemeMapper = SameScopeCredentialSchemeMapper(scope.dropLast(1)),
            )
            val client = WalletService()
            val oauth2Client = OAuth2Client()
            val state = uuid4().toString()

            suspend fun getToken(scope: String, setScopeInTokenRequest: Boolean = true): TokenResponseParameters {
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
                    scope = if (setScopeInTokenRequest) scope else null,
                    resource = issuer.metadata.credentialIssuer
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

        }
    } - {
        test("request one credential, using scope") {
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val credential = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                ).getOrThrow().shouldBeSingleton().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
            val serializedCredential = credential.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()

            JwsCompactTyped<VerifiableCredentialJws>(
                serializedCredential
            ).payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>()
        }

        test("reject credential whose required scope is only a substring of the granted scope") {
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val grantedFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val token = it.getToken(grantedFormat.scope.shouldNotBeNull())

            val requiredFormat = it.client
                .selectSupportedCredentialFormat(requestOptions, it.substringScopeIssuer.metadata)
                .shouldNotBeNull()
            // The granted scope contains the required one as a substring, but does not grant it
            grantedFormat.scope.shouldNotBeNull() shouldContain requiredFormat.scope.shouldNotBeNull()

            // Both issuers use the same credential identifiers, so the request is built against the issuer
            // that granted the scope, and then sent to the one that requires the substring scope
            val params = it.client.createCredential(
                tokenResponse = token,
                metadata = it.issuer.metadata,
                credentialFormat = grantedFormat,
                clientNonce = it.substringScopeIssuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            shouldThrow<OAuth2Exception.InvalidToken> {
                it.substringScopeIssuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = params,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        test("authorize from validated access token instead of token info") {
            val fixture = it
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = fixture.client.selectSupportedCredentialFormat(
                requestOptions,
                fixture.issuer.metadata,
            )
                .shouldNotBeNull()
            val requiredScope = credentialFormat.scope.shouldNotBeNull()
            val token = fixture.getToken(requiredScope)
            val restrictedScope = requiredScope.dropLast(1)

            val adapter = object : OAuth2AuthorizationServerAdapter by fixture.authorizationService {
                override suspend fun validateAccessToken(
                    authorizationHeader: String,
                    httpRequest: RequestInfo?,
                ): KmmResult<ValidatedAccessToken> = catching {
                    fixture.authorizationService.validateAccessToken(authorizationHeader, httpRequest)
                        .getOrThrow().copy(scope = restrictedScope)
                }

                override suspend fun getTokenInfo(
                    authorizationHeader: String,
                    httpRequest: RequestInfo?,
                ): KmmResult<TokenInfo> = catching {
                    TokenInfo(token = token.accessToken, scope = requiredScope)
                }
            }
            val issuer = CredentialIssuer(
                authorizationService = adapter,
                issuer = IssuerAgent(
                    identifier = "https://validated-token.example.com".toUri(),
                    randomSource = RandomSource.Default,
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                credentialSchemeMapper = fixture.mapper,
            )
            val params = fixture.client.createCredential(
                tokenResponse = token,
                metadata = issuer.metadata,
                credentialFormat = credentialFormat,
                clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
            ).getOrThrow().shouldBeSingleton().first()

            shouldThrow<OAuth2Exception.InvalidToken> {
                issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = params,
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        test("request multiple credentials with one JWT access token, using scope") {
            // Same as the test below, but with sender-constrained JWT access tokens instead of bearer tokens:
            // one access token must authorize more than one credential request
            val tokenUrl = "https://jwt-issuer.example.com/token"
            val tokenService = TokenService.jwt()
            val authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = CredentialAuthorizationServiceStrategy(
                    credentialSchemes = AttributeIndex.schemeSet,
                    mapper = it.mapper,
                ),
                tokenService = tokenService,
            )
            val issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://jwt-issuer.example.com".toUri(),
                    randomSource = RandomSource.Default,
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                credentialSchemeMapper = it.mapper,
            )
            val signDpop = SignJwt<JsonWebToken>(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk())

            val requestOptions = setOf(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                RequestOptions(AtomicAttribute2023, ISO_MDOC),
            ).associateBy { requestOption ->
                it.client.selectSupportedCredentialFormat(requestOption, issuer.metadata)!!
            }
            val scope = requestOptions.keys.joinToString(" ") { it.scope.shouldNotBeNull() }

            val authnRequest = it.oauth2Client.createAuthRequestJar(
                state = it.state,
                scope = scope,
                resource = issuer.metadata.credentialIssuer,
            )
            val code = authorizationService
                .authorize(authnRequest as RequestParameters) { catching { DummyUserProvider.user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .params?.code.shouldNotBeNull()
            @Suppress("DEPRECATION")
            val token = authorizationService.token(
                request = it.oauth2Client.createTokenRequestParameters(
                    state = it.state,
                    authorization = OAuth2Client.AuthorizationForToken.Code(code),
                    scope = scope,
                    resource = issuer.metadata.credentialIssuer,
                ),
                httpRequest = RequestInfo(
                    url = tokenUrl,
                    method = HttpMethod.Post,
                    dpop = BuildDPoPHeader(
                        signDpop = signDpop,
                        url = tokenUrl,
                        nonce = authorizationService.getDpopNonce(),
                        randomSource = RandomSource.Default,
                    ),
                ),
            ).getOrThrow()

            val credentialUrl = issuer.metadata.credentialEndpointUrl.shouldNotBeNull()
            requestOptions.keys.forEach { credentialFormat ->
                @Suppress("DEPRECATION")
                issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    ).getOrThrow().shouldBeSingleton().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                    request = RequestInfo(
                        url = credentialUrl,
                        method = HttpMethod.Post,
                        dpop = BuildDPoPHeader(
                            signDpop = signDpop,
                            url = credentialUrl,
                            accessToken = token.accessToken,
                            nonce = authorizationService.getDpopNonce(),
                            randomSource = RandomSource.Default,
                        ),
                    ),
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response
                    .credentials.shouldNotBeEmpty()
            }
        }

        test("request multiple credentials, using scope") {
            val requestOptions = setOf(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                RequestOptions(AtomicAttribute2023, ISO_MDOC),
            ).associateBy { requestOption ->
                it.client.selectSupportedCredentialFormat(requestOption, it.issuer.metadata)!!
            }
            val scope = requestOptions.keys.joinToString(" ") { it.scope.shouldNotBeNull() }
            val token = it.getToken(scope)

            requestOptions.forEach { requestOption ->
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = it.issuer.metadata,
                        credentialFormat = requestOption.key,
                        clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    ).getOrThrow().shouldBeSingleton().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
                    .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                    .response
                    .credentials.shouldNotBeEmpty()
                    .map { it.credentialString.shouldNotBeNull() }.any {
                        catchingUnwrapped { it.assertSdJwtReceived() }.isSuccess
                    }
            }
        }
    }
}

private fun String.assertSdJwtReceived(): Int =
    JwsCompactTyped<VerifiableCredentialSdJwt>(
        substringBefore("~")
    ).payload.disclosureDigests
        .shouldNotBeNull()
        .size shouldBeGreaterThan 1
