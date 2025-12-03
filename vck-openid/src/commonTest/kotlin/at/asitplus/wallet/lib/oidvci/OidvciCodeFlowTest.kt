package at.asitplus.wallet.lib.oidvci

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
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oauth2.ClientAuthRequest
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.WalletService.RequestOptions
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
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

val OidvciCodeFlowTest by testSuite {

    withFixtureGenerator {
        object {
            val mapper = DefaultCredentialSchemeMapper()
            val strategy = CredentialAuthorizationServiceStrategy(
                credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
                mapper = mapper,
            )
            var authorizationService = SimpleAuthorizationService(
                strategy = strategy,
            )
            var issuer = CredentialIssuer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = setOf(AtomicAttribute2023, MobileDrivingLicenceScheme),
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

            JwsSigned.deserialize<VerifiableCredentialJws>(
                VerifiableCredentialJws.serializer(),
                serializedCredential,
                vckJsonSerializer
            ).getOrThrow()
                .payload.vc.credentialSubject.shouldBeInstanceOf<at.asitplus.wallet.lib.data.AtomicAttribute2023>()

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

        test("proof over different keys leads to different credentials") {
            val requestOptions = RequestOptions(AtomicAttribute2023, PLAIN_JWT)
            val scope = it.client.selectSupportedCredentialFormat(
                requestOptions,
                it.issuer.metadata
            )?.scope.shouldNotBeNull()
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
                JwsSigned.deserialize<VerifiableCredentialJws>(
                    VerifiableCredentialJws.serializer(),
                    it.credentialString.shouldNotBeNull(),
                    vckJsonSerializer
                ).getOrThrow().payload.subject
            }.toSet().shouldHaveSize(2)
        }

        test("authorizationService with defect mapstore leads to an error") {
            it.authorizationService = SimpleAuthorizationService(
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
            val scope = it.client.selectSupportedCredentialFormat(
                requestOptions,
                it.issuer.metadata
            )?.scope.shouldNotBeNull()

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
                credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC),
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
                credentialConfigurationId = it.mapper.toCredentialIdentifier(AtomicAttribute2023, ISO_MDOC),
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

        "request credential with unknown configuration_id" { it ->
            // that credential format (from which credential_configuration_id will be derived) is not known to our issuer
            val credentialFormat = with(
                CredentialIssuer(
                    authorizationService = SimpleAuthorizationService(
                        strategy = CredentialAuthorizationServiceStrategy(setOf(EuPidScheme)),
                    ),
                    issuer = IssuerAgent(
                        identifier = "https://secondissuer.example.com".toUri(),
                        randomSource = RandomSource.Default
                    ),
                    credentialSchemes = setOf(EuPidScheme),
                )
            ) {
                it.client.selectSupportedCredentialFormat(RequestOptions(EuPidScheme, SD_JWT), metadata)
            }

            val scope = credentialFormat?.scope.shouldNotBeNull()
            val token = it.getToken(scope)

            shouldThrow<OAuth2Exception.UnknownCredentialConfiguration> {
                it.issuer.credential(
                    authorizationHeader = token.toHttpHeaderValue(),
                    params = it.client.createCredential(
                        tokenResponse = token,
                        metadata = it.issuer.metadata,
                        credentialFormat = credentialFormat,
                        clientNonce = it.issuer.nonceWithDpopNonce().getOrThrow().response.clientNonce,
                    ).getOrThrow().shouldBeSingleton().first(),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
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
                    ).getOrThrow().shouldBeSingleton().first().wrongCredentialConfigurationId(scope),
                    credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
                ).getOrThrow()
            }
        }


        "request credential in ISO MDOC, using scope" { it ->
            val requestOptions = RequestOptions(MobileDrivingLicenceScheme, ISO_MDOC)
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
                serializedCredential.decodeToByteArray(
                    Base64()
                )
            )

            val namespaces = issuerSigned.namespaces
                .shouldNotBeNull()

            namespaces.keys.first() shouldBe MobileDrivingLicenceScheme.isoNamespace
            val numberOfClaims = namespaces.values.firstOrNull()?.entries?.size.shouldNotBeNull()
            numberOfClaims shouldBeGreaterThan 1
        }
    }
}

private fun String.assertSdJwtReceived(): Int = JwsSigned.deserialize(
    VerifiableCredentialSdJwt.serializer(),
    substringBefore("~")
).getOrThrow().payload.disclosureDigests
    .shouldNotBeNull()
    .size shouldBeGreaterThan 1

private fun WalletService.CredentialRequest.wrongCredentialIdentifier(mapper: DefaultCredentialSchemeMapper) = when (this) {
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
