package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.openid.toFormParameters
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifySdJwtCredential
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oauth2.toHttpResponse
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer
import at.asitplus.wallet.lib.oidvci.toHttpResponse
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.assertions.fail
import io.kotest.engine.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*

/**
 * Tests [OpenId4VciKtorClient] against [OpenId4VciServer] with our own internal [SimpleAuthorizationService].
 *
 * Makes sure that the [OpenId4VciKtorClient] and [OAuth2KtorClient] use the DPoP nonce provided in success responses too.
 */
val OpenId4VciKtorClientIntegratedDPoPTest by matrixSuite {

    data class Context(
        val attributes: Map<String, String>,
        val credentialKeyMaterial: KeyMaterial,
        val clientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val openId4VciServer: OpenId4VciServer,
        val authorizationService: SimpleAuthorizationService,
        val client: OpenId4VciKtorClient,
    )

    fixture {
        runBlocking {
            val scheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)

            val representation = SD_JWT
            val attributes = mapOf(EuPidSdJwtDataElements.FAMILY_NAME to uuid4().toString())
            val credentialKeyMaterial = EphemeralKeyWithoutCert()
            val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
            val credentialSchemes = setOf(scheme)
            val authorizationEndpointPath = "/authorize"
            val tokenEndpointPath = "/token"
            val credentialEndpointPath = "/credential"
            val nonceEndpointPath = "/nonce"
            val parEndpointPath = "/par"
            val challengeEndpointPath = "/challenge"
            val publicContext = "https://issuer.example.com"
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
                publicContext = publicContext,
                authorizationEndpointPath = authorizationEndpointPath,
                tokenEndpointPath = tokenEndpointPath,
                pushedAuthorizationRequestEndpointPath = parEndpointPath,
                challengeEndpointPath = challengeEndpointPath,
                clientAuthenticationService = AttestationBasedClientAuthenticationService(),
                tokenService = TokenService.jwt(
                    issueRefreshTokens = true
                ),
            )
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val openId4VciServer = OpenId4VciServer(
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
                        respond(openId4VciServer.metadataHttpResponse(request.headers[HttpHeaders.Accept]).getOrThrow())

                    request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                        respond(authorizationService.metadata().toHttpResponse())

                    request.url.fullPath.startsWith(parEndpointPath) -> {
                        val requestBody = request.body.toByteArray().decodeToString()
                        val authnRequest: RequestParameters =
                            RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                        authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                            onSuccess = { respond(it.toHttpResponse()) },
                            onFailure = { respondOAuth2Error(it) }
                        )
                    }

                    request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                        val requestBody = request.body.toByteArray().decodeToString()
                        val queryParameters: Map<String, String> =
                            request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                        val authnRequest: RequestParameters =
                            if (requestBody.isEmpty()) RequestParametersSerializer.decodeFormParameters(queryParameters)
                            else RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                        authorizationService.authorize(authnRequest) { this.catching { TestUtils.dummyUser() } }.fold(
                            onSuccess = { respond(it.toHttpResponse()) },
                            onFailure = { fail("$authorizationEndpointPath should not return an error") }
                        )
                    }

                    request.url.fullPath.startsWith(tokenEndpointPath) -> {
                        val requestBody = request.body.toByteArray().decodeToString()
                        val params: TokenRequestParameters = requestBody.decodeFromFormUrlEncoded<TokenRequestParameters>()
                        authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                            onSuccess = { respond(it.toHttpResponse()) },
                            onFailure = { fail("$tokenEndpointPath should not return an error") }
                        )
                    }

                    request.url.fullPath.startsWith(nonceEndpointPath) -> {
                        respond(openId4VciServer.nonceWithDpopNonce().getOrThrow().toHttpResponse())
                    }

                    request.url.fullPath.startsWith(challengeEndpointPath) -> {
                        authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
                            .let { respond(it.toHttpResponse()) }
                    }

                    request.url.fullPath.startsWith(credentialEndpointPath) -> {
                        val requestBody = request.body.toByteArray().decodeToString()
                        val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                        openId4VciServer.credential(
                            authorizationHeader = authn,
                            params = OpenId4VciClient.CredentialRequest.parse(requestBody).getOrThrow(),
                            credentialDataProvider = TestUtils.credentialDataProviderFun(
                                scheme,
                                representation,
                                attributes
                            ),
                            request = request.toRequestInfo(),
                        ).fold(
                            onSuccess = { respond(it.toHttpResponse()) },
                            onFailure = { fail("$credentialEndpointPath should not return an error") }
                        )
                    }

                    else -> respondError(HttpStatusCode.NotFound)
                        .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
                }
            }
            val clientId = "https://example.com/rp"
            Context(
                attributes = attributes,
                credentialKeyMaterial = credentialKeyMaterial,
                clientAuthKeyMaterial = clientAuthKeyMaterial,
                mockEngine = mockEngine,
                openId4VciServer = openId4VciServer,
                authorizationService = authorizationService,
                client = OpenId4VciKtorClient(
                    httpClient = HttpClient(mockEngine),
                    oauth2Client = OAuth2Client(clientId = clientId),
                    vciClient = OpenId4VciClient(keyMaterial = credentialKeyMaterial),
                    clientAttestation = ClientAttestation(clientAuthKeyMaterial) {
                        catching {
                            BuildClientAttestationJwt(
                                SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                                clientId = clientId,
                                clientKey = clientAuthKeyMaterial.jsonWebKey
                            )
                        }
                    },
                )
            )
        }
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
