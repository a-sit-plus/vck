package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondIncludingDpopNonce
import at.asitplus.wallet.lib.ktor.openid.TestUtils.toRequestInfo
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifySdJwtCredential
import at.asitplus.wallet.lib.ktor.openid.toCredentialRenewalInfo
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.github.aakira.napier.Napier
import io.kotest.assertions.fail
import io.kotest.matchers.nulls.shouldNotBeNull
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] with our own internal [SimpleAuthorizationService].
 *
 * Makes sure that the [OpenId4VciClient] and [OAuth2KtorClient] use the DPoP nonce provided in success responses too.
 */
val OpenId4VciClientIntegratedDPoPTest by testSuite {

    data class Context(
        val attributes: Map<String, String>,
        val credentialKeyMaterial: KeyMaterial,
        val dpopKeyMaterial: KeyMaterial,
        val clientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val credentialIssuer: CredentialIssuer,
        val authorizationService: SimpleAuthorizationService,
        val client: OpenId4VciClient,
    )

    withFixtureGenerator {
        val scheme = EuPidScheme
        val representation = SD_JWT
        val attributes = mapOf(EuPidScheme.Attributes.FAMILY_NAME to uuid4().toString())
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val dpopKeyMaterial = EphemeralKeyWithoutCert()
        val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        val credentialSchemes = setOf<at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme>(scheme)
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
        )
        val mockEngine = MockEngine { request ->
            when {
                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer ->
                    this.respond(credentialIssuer.metadata)

                request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                    this.respond(authorizationService.metadata())

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody<RequestParameters>()
                    authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { fail("$parEndpointPath should not return an error") }
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery<RequestParameters>()
                        else requestBody.decodeFromPostBody<RequestParameters>()
                    authorizationService.authorize(authnRequest) { this.catching { TestUtils.dummyUser() } }.fold(
                        onSuccess = { this.respondRedirect(it.url) },
                        onFailure = { fail("$authorizationEndpointPath should not return an error") }
                    )
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respondIncludingDpopNonce(it) },
                        onFailure = { fail("$tokenEndpointPath should not return an error") }
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    this.respond(credentialIssuer.nonceWithDpopNonce().getOrThrow())
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    credentialIssuer.credential(
                        authorizationHeader = authn,
                        params = WalletService.CredentialRequest.parse(requestBody).getOrThrow(),
                        credentialDataProvider = TestUtils.credentialDataProviderFun(
                            scheme,
                            representation,
                            attributes
                        ),
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { this.respond(it) },
                        onFailure = { fail("$credentialEndpointPath should not return an error") }
                    )
                }

                else -> this.respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
        Context(
            attributes = attributes,
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
            )
        )
    } - {
        test("loadEuPidCredentialSdJwt") { context ->
            var refreshTokenStore: CredentialRenewalInfo? = null

            val credentialIdentifierInfos = context.client.loadCredentialMetadata("http://localhost").getOrThrow()
            val selectedCredential = credentialIdentifierInfos
                .first { it.supportedCredentialFormat.format == CredentialFormatEnum.DC_SD_JWT }

            context.client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = "http://localhost",
                credentialIdentifierInfo = selectedCredential,
            ).getOrThrow().also {
                // Simulates the browser, handling authorization to get the authCode
                val httpClient = HttpClient(context.mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it.url).headers[HttpHeaders.Location]
                context.client.resumeWithAuthCode(authCode!!, it.context).getOrThrow().also {
                    refreshTokenStore = it.refreshToken!!
                    context.attributes.forEach { (key, value) ->
                        it.verifySdJwtCredential(key, value, context.credentialKeyMaterial.publicKey)
                    }
                }
            }

            refreshTokenStore.shouldNotBeNull()
            context.client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                context.attributes.forEach { (key, value) ->
                    it.verifySdJwtCredential(key, value, context.credentialKeyMaterial.publicKey)
                }
            }
        }
    }
}
