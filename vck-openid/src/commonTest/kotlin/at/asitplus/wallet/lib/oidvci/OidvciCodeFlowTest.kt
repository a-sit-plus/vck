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
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialResponseSingleCredential
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ExtractedSdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowExactly
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.maps.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

val OidvciCodeFlowTest by matrixSuite {

    fixture {
        object {
            val mapper = DefaultCredentialSchemeMapper()
            val strategy = CredentialAuthorizationServiceStrategy(
                credentialSchemes = AttributeIndex.schemeSet,
                mapper = mapper,
            )
            var authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                strategy = strategy,
            )
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                credentialSchemeMapper = mapper,
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

            suspend fun getToken(
                authorizationDetails: Set<AuthorizationDetails>,
                setAuthnDetailsInTokenRequest: Boolean = true,
            ): TokenResponseParameters {
                val authnRequest = oauth2Client.createAuthRequestJar(
                    state = state,
                    authorizationDetails = authorizationDetails
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
                    authorizationDetails = if (setAuthnDetailsInTokenRequest) authorizationDetails else null,
                )
                return authorizationService.token(tokenRequest, null).getOrThrow()
            }

            fun defectMapStore() = object : MapStore<String, ClientAuthRequest> {
                override suspend fun put(key: String, value: ClientAuthRequest) = Unit
                override suspend fun get(key: String): ClientAuthRequest? = null
                override suspend fun remove(key: String): ClientAuthRequest? = null
            }
        }
    } - {
        test("metadata validation") {
            val issuerCredentialFormats = it.issuer.metadata.supportedCredentialConfigurations.shouldNotBeNull()
                .shouldNotBeEmpty()
            issuerCredentialFormats.forEach { entry: Map.Entry<String, SupportedCredentialFormat> ->
                entry.key.shouldNotBeEmpty()
                entry.value.shouldNotBeNull().apply {
                    format.shouldNotBeNull()
                    scope.shouldNotBeEmpty()
                    supportedSigningAlgorithms.shouldNotBeNull().shouldNotBeEmpty()
                    supportedProofTypes.shouldNotBeNull().shouldNotBeEmpty()
                    supportedBindingMethods.shouldNotBeNull().shouldNotBeEmpty()
                    if (format != CredentialFormatEnum.JWT_VC) {
                        credentialMetadata.shouldNotBeNull().claimDescription.shouldNotBeNull()
                            .shouldNotBeEmpty()
                    }
                }
            }
            it.strategy.validAuthorizationDetails("empty").shouldNotBeEmpty().forEach {
                it.shouldBeInstanceOf<OpenIdAuthorizationDetails>()
                    .credentialConfigurationId.shouldNotBeEmpty()
                    .shouldBeIn(issuerCredentialFormats.keys)
            }
        }

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
            ).payload.vc.credentialSubject.shouldBeInstanceOf<JsonElement>().also { credentialSubject ->
                shouldNotThrowAny {
                    Json.decodeFromJsonElement(
                        at.asitplus.wallet.lib.data.AtomicAttribute2023.serializer(),
                        credentialSubject
                    )
                }
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
                    .credentials.shouldNotBeEmpty().first()
                    .credentialString.shouldNotBeNull()
            }
        }

        test("nonce can only be used for one call to credential endpoint") {
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope)
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce

            it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = it.client.createCredential(
                    tokenResponse = token,
                    metadata = it.issuer.metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce,
                ).getOrThrow().shouldBeSingleton().first(),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response.credentials.shouldNotBeEmpty()
                .first().credentialString.shouldNotBeNull()

            val freshToken = it.getToken(scope)
            shouldThrowExactly<OAuth2Exception.InvalidNonce> {
                it.issuer.credential(
                    authorizationHeader = freshToken.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = freshToken,
                        metadata = it.issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = clientNonce, // same clientNonce as before!
                    ).getOrThrow().shouldBeSingleton().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        test("proof over different keys leads to different credentials") {
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val scope = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)?.scope
                .shouldNotBeNull()
            val clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce
            val token = it.getToken(scope)
            val proof = it.client.createCredentialRequestProofJwt(
                clientNonce = clientNonce,
                credentialIssuer = it.issuer.metadata.credentialIssuer,
            )
            val differentProof = WalletService().createCredentialRequestProofJwt(
                clientNonce = clientNonce,
                credentialIssuer = it.issuer.metadata.credentialIssuer,
            )
            val credentialRequest = CredentialRequestParameters(
                credentialConfigurationId = scope,
                proofs = CredentialRequestProofContainer(
                    jwt = proof.jwt!! + differentProof.jwt!!
                )
            )

            val credentials: Collection<CredentialResponseSingleCredential> = it.issuer.credential(
                authorizationHeader = token.toHttpHeaderValue(),
                params = WalletService.CredentialRequest.Plain(credentialRequest),
                credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            ).getOrThrow()
                .shouldBeInstanceOf<CredentialIssuer.CredentialResponse.Plain>()
                .response
                .credentials.shouldNotBeEmpty().shouldHaveSize(2)
            // subject identifies the key of the client, here the keys of different proofs, so they should be unique
            credentials.map {
                JwsCompactTyped<VerifiableCredentialJws>(
                    it.credentialString.shouldNotBeNull()
                ).payload.subject
            }.toSet().shouldHaveSize(2)
        }

        test("authorizationService with defect mapstore leads to an error") {
            it.authorizationService = SimpleAuthorizationService(
                requirePushedAuthorizationRequests = false,
                codeToClientAuthRequest = it.defectMapStore(),
                strategy = CredentialAuthorizationServiceStrategy(setOf(AtomicAttribute2023)),
            )
            it.issuer = CredentialIssuer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(AtomicAttribute2023),
            )
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val scope = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)?.scope
                .shouldNotBeNull()

            shouldThrow<OAuth2Exception> {
                it.getToken(scope)
            }
        }

        test("request credential in SD-JWT, using scope") {
            val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
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

            serializedCredential.assertSdJwtReceived()
        }

        test("request credential in SD-JWT, using scope only in authn request") {
            val requestOptions = RequestOptions(AtomicAttribute2023, SD_JWT)
            val credentialFormat = it.client.selectSupportedCredentialFormat(requestOptions, it.issuer.metadata)
                .shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val token = it.getToken(scope, false) // do not set scope in token request, only in authn request

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
            val serializedCredential = credential.credentials.shouldNotBeEmpty().first()
                .credentialString.shouldNotBeNull()

            serializedCredential.assertSdJwtReceived()
        }

        test("request credential in SD-JWT, using scope in access token different to auth code") {
            val authCodeScope = it.client.selectSupportedCredentialFormat(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                it.issuer.metadata
            )?.scope.shouldNotBeNull()
            val tokenScope = it.client.selectSupportedCredentialFormat(
                RequestOptions(AtomicAttribute2023, ISO_MDOC),
                it.issuer.metadata
            )?.scope.shouldNotBeNull()
            val authnRequest = it.oauth2Client.createAuthRequestJar(
                state = it.state,
                scope = authCodeScope,
                resource = it.issuer.metadata.credentialIssuer
            )
            val input = authnRequest as RequestParameters
            val authnResponse = it.authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()
            val tokenRequest = it.oauth2Client.createTokenRequestParameters(
                state = it.state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                scope = tokenScope, // this is wrong, should be the same as in authn request
                resource = it.issuer.metadata.credentialIssuer
            )
            shouldThrow<OAuth2Exception> {
                it.authorizationService.token(tokenRequest, null).getOrThrow()
            }
        }

        test("request credential in SD-JWT, using authorization details") {
            val credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT)
            val authorizationDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = credentialConfigurationId,
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations
                .shouldNotBeNull()[credentialConfigurationId]
                .shouldNotBeNull()
            val token = it.getToken(authorizationDetails)

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

            serializedCredential.assertSdJwtReceived()
        }

        test("request credential in SD-JWT, using authorization details only in authnrequest") {
            val credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT)
            val authorizationDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = credentialConfigurationId,
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val credentialFormat = it.issuer.metadata.supportedCredentialConfigurations
                .shouldNotBeNull()[credentialConfigurationId]
                .shouldNotBeNull()
            val token = it.getToken(authorizationDetails, false) // do not set authn details in token request

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

            serializedCredential.assertSdJwtReceived()
        }

        test("request credential in SD-JWT, using authorization details in access token different to auth code") {
            val authCodeAuthnDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT),
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val tokenAuthnDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = it.mapper.toCredentialIdentifier(
                    AtomicAttribute2023,
                    ISO_MDOC
                ),
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val authnRequest = it.oauth2Client.createAuthRequestJar(
                state = it.state,
                authorizationDetails = authCodeAuthnDetails
            )
            val input = authnRequest as RequestParameters
            val authnResponse = it.authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()
            val tokenRequest = it.oauth2Client.createTokenRequestParameters(
                state = it.state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                authorizationDetails = tokenAuthnDetails // this is wrong, should be same as in authn request
            )
            shouldThrow<OAuth2Exception> {
                it.authorizationService.token(tokenRequest, null).getOrThrow()
            }
        }

        test("request credential in SD-JWT, using more authorization details in access token than in auth code") {
            val authCodeAuthnDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT),
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val tokenAuthnDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = it.mapper.toCredentialIdentifier(
                    AtomicAttribute2023,
                    ISO_MDOC
                ),
                authorizationServers = it.issuer.metadata.authorizationServers
            )
            val authnRequest = it.oauth2Client.createAuthRequestJar(
                state = it.state,
                authorizationDetails = authCodeAuthnDetails
            )
            val input = authnRequest as RequestParameters
            val authnResponse = it.authorizationService.authorize(input) { catching { DummyUserProvider.user } }
                .getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val code = authnResponse.params?.code
                .shouldNotBeNull()
            val tokenRequest = it.oauth2Client.createTokenRequestParameters(
                state = it.state,
                authorization = OAuth2Client.AuthorizationForToken.Code(code),
                authorizationDetails = tokenAuthnDetails + authCodeAuthnDetails // this is wrong, should be same as in authn request
            )
            shouldThrow<OAuth2Exception> {
                it.authorizationService.token(tokenRequest, null).getOrThrow()
            }
        }

        /**
         * Only the scopes the authorization server accepted may be granted. It used to keep the client's raw scope
         * string with the authorization code, so an unsupported value alongside a supported one ended up in the
         * access token unvalidated.
         */
        "reject a token request for a scope that was not accepted in the authorization request" { it ->
            val credentialFormat = it.client.selectSupportedCredentialFormat(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                it.issuer.metadata
            )
            val scope = credentialFormat?.scope.shouldNotBeNull()

            shouldThrow<OAuth2Exception> {
                it.getToken("$scope urn:unknown:scope")
            }
        }

        "reject a scope for a configuration_id unknown to the authorization server" { it ->
            // that credential format (from which credential_configuration_id will be derived) is not known to our
            // issuer: a typed SD-JWT scheme that is never registered with AttributeIndex (so not in the issuer's
            // schemeSet), unlike the metadata-backed schemes pre-loaded via the TestConfig registry
            val scheme = ExtractedSdJwtCredentialScheme(
                sdJwtType = "urn:eudi:unknown:1",
                claimDescriptions = emptySet(),
            )
            val credentialFormat = with(
                CredentialIssuer(
                    authorizationService = SimpleAuthorizationService(
                        requirePushedAuthorizationRequests = false,
                        strategy = CredentialAuthorizationServiceStrategy(setOf(scheme)),
                    ),
                    issuer = IssuerAgent(
                        identifier = "https://secondissuer.example.com".toUri(),
                        randomSource = RandomSource.Default
                    ),
                    credentialSchemes = setOf(scheme),
                )
            ) {
                it.client.selectSupportedCredentialFormat(RequestOptions(scheme, SD_JWT), metadata)
            }

            val scope = credentialFormat?.scope.shouldNotBeNull()

            // The authorization server must not issue a token for a scope it does not know. It used to strip the
            // unknown value, leaving an empty scope, and only the wallet then noticed the mismatch.
            shouldThrow<OAuth2Exception.InvalidScope> {
                it.getToken(scope)
            }
        }

        "request credential in SD-JWT, using scope in token, but authorization details in credential request" { it ->
            val credentialFormat = it.client.selectSupportedCredentialFormat(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                it.issuer.metadata
            )
            val scope = credentialFormat
                ?.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            shouldThrow<OAuth2Exception> {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = it.issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    ).getOrThrow().shouldBeSingleton().first().wrongCredentialIdentifier(it.mapper),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }

        "request credential in SD-JWT, using authorization details in token, but scope in credential request" { it ->
            val credentialFormat = it.client.selectSupportedCredentialFormat(
                RequestOptions(AtomicAttribute2023, SD_JWT),
                it.issuer.metadata
            ).shouldNotBeNull()
            val scope = credentialFormat.scope.shouldNotBeNull()
            val authorizationDetails = it.client.buildAuthorizationDetails(
                credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT),
                authorizationServers = it.issuer.metadata.authorizationServers
            )

            shouldThrow<OAuth2Exception> {
                val token = it.getToken(authorizationDetails)
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = it.issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    ).getOrThrow().shouldBeSingleton().first()
                        .wrongCredentialConfigurationId(scope),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }


        "request credential in ISO MDOC, using scope" { it ->
            val requestOptions = RequestOptions(AttributeIndex.resolveIdentifier(MDL_DOCTYPE, ISO_MDOC), ISO_MDOC)
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

            val issuerSigned = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(
                serializedCredential.decodeToByteArray(Base64())
            )

            val namespaces = issuerSigned.namespaces.shouldNotBeNull()
            namespaces.keys.first() shouldBe "org.iso.18013.5.1"
            val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
            numberOfClaims shouldBeGreaterThan 1
        }
    }
}

private fun String.assertSdJwtReceived(): Int = JwsCompactTyped<VerifiableCredentialSdJwt>(
    substringBefore("~")
).payload.disclosureDigests
    .shouldNotBeNull()
    .size shouldBeGreaterThan 1

private fun WalletService.CredentialRequest.wrongCredentialIdentifier(mapper: DefaultCredentialSchemeMapper) =
    when (this) {
        is WalletService.CredentialRequest.Encrypted -> this
        is WalletService.CredentialRequest.Plain -> WalletService.CredentialRequest.Plain(
            this.request.copy(
                // enforces error on client, setting credential_identifier, although access token was for scope
                // (which should be credential_configuration_id in credential request)
                credentialIdentifier = mapper.toCredentialIdentifier(AtomicAttribute2023, SD_JWT),
                credentialConfigurationId = null,
            )
        )
    }

private fun WalletService.CredentialRequest.wrongCredentialConfigurationId(scope: String) = when (this) {
    is WalletService.CredentialRequest.Encrypted -> this
    is WalletService.CredentialRequest.Plain -> WalletService.CredentialRequest.Plain(
        this.request.copy(
            // enforces error on client, setting credential_configuration_id, although access token was for
            // authorization details (which should be credential_identifier in credential request)
            credentialConfigurationId = scope,
            credentialIdentifier = null
        )
    )
}
