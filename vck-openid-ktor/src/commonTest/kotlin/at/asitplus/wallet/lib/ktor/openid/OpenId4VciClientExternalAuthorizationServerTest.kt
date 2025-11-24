package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.Iso
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.VcSd
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
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
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
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
import kotlin.random.Random
import kotlin.time.Clock

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] that uses [RemoteOAuth2AuthorizationServerAdapter]
 * to simulate an external OAuth2.0 Authorization Server (which is still our own internal [SimpleAuthorizationService]).
 */
val OpenId4VciClientExternalAuthorizationServerTest by testSuite {

    data class Context(
        val credentialKeyMaterial: KeyMaterial,
        val walletDpopKeyMaterial: KeyMaterial,
        val walletClientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val issuerDpopKeyMaterial: KeyMaterial,
        val issuerPublicContext: String,
        val issuerClientAuthKeyMaterial: KeyMaterial,
        val credentialIssuer: CredentialIssuer,
        val externalAuthorizationServer: SimpleAuthorizationService,
        val client: OpenId4VciClient,
    )

    fun setup(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
    ): Context {
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val walletDpopKeyMaterial = EphemeralKeyWithoutCert()
        val walletClientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val issuerDpopKeyMaterial = EphemeralKeyWithoutCert()
        val issuerClientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val credentialDataProvider = CredentialDataProviderFun {
            catching {
                require(it.credentialScheme == scheme)
                require(it.credentialRepresentation == representation)
                var digestId = 0u
                when (representation) {
                    PLAIN_JWT -> TODO()
                    SD_JWT -> VcSd(
                        attributes.map { ClaimToBeIssued(it.key, it.value) },
                        Clock.System.now(),
                        it.credentialScheme,
                        it.subjectPublicKey,
                        OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                        sdAlgorithm = supportedSdAlgorithms.random()
                    )

                    ISO_MDOC -> Iso(
                        attributes.map {
                            IssuerSignedItem(digestId++, Random.nextBytes(32), it.key, it.value)
                        },
                        Clock.System.now(),
                        it.credentialScheme,
                        it.subjectPublicKey,
                        OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                    )
                }
            }
        }
        val credentialSchemes = setOf(EuPidScheme)
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val credentialEndpointPath = "/credential"
        val nonceEndpointPath = "/nonce"
        val parEndpointPath = "/par"
        val userInfoEndpointPath = "/userinfo"
        val introspectionEndpointPath = "/introspection"
        val issuerPublicContext = "https://issuer.example.com"
        val authServerPublicContext = "https://auth.example.com"
        val tokenService = TokenService.jwt(
            issueRefreshTokens = true
        )
        val externalAuthorizationServer = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
            publicContext = authServerPublicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            userInfoEndpointPath = userInfoEndpointPath,
            introspectionEndpointPath = introspectionEndpointPath,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            ),
            tokenService = tokenService,
        )
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        lateinit var credentialIssuer: CredentialIssuer
        val mockEngine = MockEngine { request ->
            when {
                request.url.toString().startsWith(issuerPublicContext) &&
                        request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer ->
                    respond(credentialIssuer.metadata)

                request.url.toString().startsWith(authServerPublicContext) &&
                        request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                    respond(externalAuthorizationServer.metadata())

                request.url.toString() == "$authServerPublicContext$parEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
                    externalAuthorizationServer.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString().startsWith("$authServerPublicContext$authorizationEndpointPath") -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    externalAuthorizationServer.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$tokenEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    externalAuthorizationServer.token(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$userInfoEndpointPath" -> {
                    val authn = request.headers[HttpHeaders.Authorization]
                    externalAuthorizationServer.userInfo(authn!!, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )

                }

                request.url.toString() == "$authServerPublicContext$introspectionEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params = requestBody.decodeFromPostBody<TokenIntrospectionRequest>()
                    externalAuthorizationServer.tokenIntrospection(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )

                }

                request.url.toString() == "$issuerPublicContext$nonceEndpointPath" -> {
                    respond(credentialIssuer.nonceWithDpopNonce().getOrThrow())
                }

                request.url.toString() == "$issuerPublicContext$credentialEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = vckJsonSerializer.decodeFromString<CredentialRequestParameters>(requestBody)
                    credentialIssuer.credential(
                        authorizationHeader = authn,
                        params = WalletService.CredentialRequest.Plain(params),
                        credentialDataProvider = credentialDataProvider,
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { respond(it) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url}") }
            }
        }
        val walletClientId = "https://example.com/rp"
        credentialIssuer = CredentialIssuer(
            authorizationService = RemoteOAuth2AuthorizationServerAdapter(
                publicContext = authServerPublicContext,
                engine = mockEngine,
                oauth2Client = OAuth2KtorClient(
                    engine = mockEngine,
                    loadClientAttestationJwt = {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = issuerPublicContext,
                            issuer = "issuer",
                            clientKey = issuerClientAuthKeyMaterial.jsonWebKey
                        ).serialize()
                    },
                    signClientAttestationPop = SignJwt(issuerClientAuthKeyMaterial, JwsHeaderNone()),
                    signDpop = SignJwt(issuerDpopKeyMaterial, JwsHeaderCertOrJwk()),
                    dpopAlgorithm = issuerDpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    oAuth2Client = OAuth2Client(clientId = issuerPublicContext),
                    randomSource = RandomSource.Default,
                ),
                internalTokenVerificationService = tokenService.verification,
            ),
            issuer = issuer,
            credentialSchemes = credentialSchemes,
            publicContext = issuerPublicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
        )
        return Context(
            credentialKeyMaterial = credentialKeyMaterial,
            walletDpopKeyMaterial = walletDpopKeyMaterial,
            walletClientAuthKeyMaterial = walletClientAuthKeyMaterial,
            mockEngine = mockEngine,
            issuerDpopKeyMaterial = issuerDpopKeyMaterial,
            issuerPublicContext = issuerPublicContext,
            issuerClientAuthKeyMaterial = issuerClientAuthKeyMaterial,
            credentialIssuer = credentialIssuer,
            externalAuthorizationServer = externalAuthorizationServer,
            client = OpenId4VciClient(
                engine = mockEngine,
                oid4vciService = WalletService(
                    clientId = walletClientId,
                    keyMaterial = credentialKeyMaterial,
                ),
                oauth2Client = OAuth2KtorClient(
                    engine = mockEngine,
                    loadClientAttestationJwt = {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = walletClientId,
                            issuer = "issuer",
                            clientKey = walletClientAuthKeyMaterial.jsonWebKey
                        ).serialize()
                    },
                    signClientAttestationPop = SignJwt(walletClientAuthKeyMaterial, JwsHeaderNone()),
                    signDpop = SignJwt(walletDpopKeyMaterial, JwsHeaderCertOrJwk()),
                    dpopAlgorithm = walletDpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                    oAuth2Client = OAuth2Client(clientId = walletClientId),
                    randomSource = RandomSource.Default,
                )
            )
        )
    }

    test("loadEuPidCredentialSdJwt") {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidScheme.Attributes.FAMILY_NAME
        with(setup(EuPidScheme, SD_JWT, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: RefreshTokenInfo? = null
            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata(issuerPublicContext).getOrThrow()
            // just pick the first credential in SD-JWT that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.DC_SD_JWT }
            // client will call clientBrowser.openUrlExternally
            client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = issuerPublicContext,
                credentialIdentifierInfo = selectedCredential,
            ).getOrThrow().also {
                // Simulates the browser, handling authorization to get the authCode
                val httpClient = HttpClient(mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it.url).headers[HttpHeaders.Location]
                client.resumeWithAuthCode(authCode!!, it.context).getOrThrow().also {
                    refreshTokenStore = it.refreshToken!!
                    it.verifySdJwtCredential(
                        expectedAttributeName,
                        expectedAttributeValue,
                        credentialKeyMaterial.publicKey
                    )
                }
            }

            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifySdJwtCredential(
                    expectedAttributeName,
                    expectedAttributeValue,
                    credentialKeyMaterial.publicKey
                )
            }
        }
    }

    test("loadEuPidCredentialIsoWithOffer") {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidScheme.Attributes.GIVEN_NAME
        with(setup(EuPidScheme, ISO_MDOC, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: RefreshTokenInfo? = null
            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata(issuerPublicContext).getOrThrow()
            // just pick the first credential in MSO_MDOC that is available
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.MSO_MDOC }

            val offer = externalAuthorizationServer.credentialOfferWithPreAuthnForUser(
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
