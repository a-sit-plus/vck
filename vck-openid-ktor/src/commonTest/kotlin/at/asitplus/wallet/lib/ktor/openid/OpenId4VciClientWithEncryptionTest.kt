package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.credentialDataProviderFun
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.ktor.openid.TestUtils.toRequestInfo
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifyIsoMdocCredential
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifySdJwtCredential
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.IssuerEncryptionService
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.github.aakira.napier.Napier
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] with our own internal [SimpleAuthorizationService].
 */
val OpenId4VciClientWithEncryptionTest by testSuite {

    data class Context(
        val credentialKeyMaterial: KeyMaterial,
        val dpopKeyMaterial: KeyMaterial,
        val clientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val credentialIssuer: CredentialIssuer,
        val authorizationService: SimpleAuthorizationService,
        val client: OpenId4VciClient,
    )

    fun setup(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
    ): Context {
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val dpopKeyMaterial = EphemeralKeyWithoutCert()
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val credentialSchemes = setOf(scheme)
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val credentialEndpointPath = "/credential"
        val nonceEndpointPath = "/nonce"
        val parEndpointPath = "/par"
        val publicContext = "https://issuer.example.com"
        val authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            ),
            tokenService = TokenService.jwt(
                issueRefreshTokens = true
            ),
        )
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = issuer,
            credentialSchemes = credentialSchemes,
            publicContext = publicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
            // that's crucial: require encryption
            encryptionService = IssuerEncryptionService(
                requireResponseEncryption = true,
                requireRequestEncryption = true
            )
        )
        val mockEngine = MockEngine.Companion { request ->
            when {
                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer -> respond(
                    vckJsonSerializer.encodeToString<IssuerMetadata>(credentialIssuer.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
                    authorizationService.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    authorizationService.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.token(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    respond(credentialIssuer.nonceWithDpopNonce().getOrThrow())
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    credentialIssuer.credential(
                        authorizationHeader = authn,
                        params = WalletService.CredentialRequest.parse(requestBody).getOrThrow(),
                        credentialDataProvider = credentialDataProviderFun(scheme, representation, attributes),
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"

        return Context(
            credentialKeyMaterial = credentialKeyMaterial,
            dpopKeyMaterial = dpopKeyMaterial,
            clientAuthKeyMaterial = clientAuthKeyMaterial,
            mockEngine = mockEngine,
            credentialIssuer = credentialIssuer,
            authorizationService = authorizationService,
            client = OpenId4VciClient(
                engine = mockEngine,
                oid4vciService = WalletService(
                    clientId = clientId,
                    keyMaterial = credentialKeyMaterial,
                ),
                oauth2Client = OAuth2KtorClient(
                    engine = mockEngine,
                    loadClientAttestationJwt = {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = clientId,
                            issuer = "issuer",
                            clientKey = clientAuthKeyMaterial.jsonWebKey
                        ).serialize()
                    },
                    signClientAttestationPop = SignJwt(clientAuthKeyMaterial, JwsHeaderNone()),
                    signDpop = SignJwt(dpopKeyMaterial, JwsHeaderCertOrJwk()),
                    dpopAlgorithm = dpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    oAuth2Client = OAuth2Client(clientId = clientId),
                    randomSource = RandomSource.Default,
                )
            ),
        )
    }

    test("loadEuPidCredentialSdJwt") {
        val expectedFamilyName = uuid4().toString()
        val expectedAttributeName = EuPidScheme.Attributes.FAMILY_NAME
        with(setup(EuPidScheme, SD_JWT, mapOf(expectedAttributeName to expectedFamilyName))) {
            var refreshTokenStore: RefreshTokenInfo? = null

            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
            // just pick the first credential in SD-JWT that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.DC_SD_JWT }
            // client will call clientBrowser.openUrlExternally
            client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = "http://localhost",
                credentialIdentifierInfo = selectedCredential,
            ).getOrThrow().also {
                // Simulates the browser, handling authorization to get the authCode
                val httpClient = HttpClient(mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it.url).headers[HttpHeaders.Location]
                client.resumeWithAuthCode(authCode!!, it.context).getOrThrow().also {
                    refreshTokenStore = it.refreshToken!!
                    it.verifySdJwtCredential(expectedAttributeName, expectedFamilyName, credentialKeyMaterial.publicKey)
                }
            }

            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifySdJwtCredential(expectedAttributeName, expectedFamilyName, credentialKeyMaterial.publicKey)
            }
        }
    }

    test("loadEuPidCredentialIsoWithOffer") {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidScheme.Attributes.GIVEN_NAME
        with(setup(EuPidScheme, ISO_MDOC, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: RefreshTokenInfo? = null

            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
            // just pick the first credential in MSO_MDOC that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.MSO_MDOC }

            val offer = authorizationService.credentialOfferWithPreAuthnForUser(
                dummyUser(),
                credentialIssuer.metadata.credentialIssuer
            )
            client.loadCredentialWithOfferReturningResult(offer, selectedCredential, null).getOrThrow().also {
                it.shouldBeInstanceOf<CredentialIssuanceResult.Success>().also {
                    refreshTokenStore = it.refreshToken!!
                    it.verifyIsoMdocCredential(expectedAttributeName, expectedAttributeValue)
                }
            }
            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifyIsoMdocCredential(expectedAttributeName, expectedAttributeValue)
            }
        }
    }
}
