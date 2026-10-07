package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.openid.toFormParameters
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupid.EuPidDataElements
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.Iso
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.VcSd
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.ktor.openid.TestUtils.dummyUser
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respond
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondOAuth2Error
import at.asitplus.wallet.lib.ktor.openid.TestUtils.respondResourceServerError
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifyIsoMdocCredential
import at.asitplus.wallet.lib.ktor.openid.TestUtils.verifySdJwtCredential
import at.asitplus.wallet.lib.oauth2.AttestationBasedClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oauth2.toHttpResponse
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer
import at.asitplus.wallet.lib.oidvci.toHttpResponse
import com.benasher44.uuid.uuid4
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
import kotlin.time.Duration.Companion.minutes

/**
 * Tests [OpenId4VciKtorClient] against [OpenId4VciServer] that uses [RemoteOAuth2AuthorizationServerAdapter]
 * to simulate an external OAuth2.0 Authorization Server (which is still our own internal [SimpleAuthorizationService]).
 */
val OpenId4VciKtorClientExternalAuthorizationServerTest by matrixSuite {

    data class Context(
        val credentialKeyMaterial: KeyMaterial,
        val walletClientAuthKeyMaterial: KeyMaterial,
        val mockEngine: MockEngine,
        val issuerPublicContext: String,
        val issuerClientAuthKeyMaterial: KeyMaterial,
        val openId4VciServer: OpenId4VciServer,
        val externalAuthorizationServer: SimpleAuthorizationService,
        val client: OpenId4VciKtorClient,
    )

    fun setup(
        scheme: CredentialScheme,
        representation: CredentialRepresentation,
        attributes: Map<String, String>,
        validatePopAudience: Boolean = false,
    ): Context {
        val credentialKeyMaterial = EphemeralKeyWithoutCert()
        val walletClientAuthKeyMaterial = EphemeralKeyWithoutCert()
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
                        Clock.System.now().plus(1.minutes),
                        it.credentialScheme as SdJwtCredentialScheme,
                        it.subjectPublicKey,
                        OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                        sdAlgorithm = Digest.SHA256
                    )

                    ISO_MDOC -> Iso(
                        attributes.map {
                            IssuerSignedItem(digestId++, Random.nextBytes(32), it.key, it.value)
                        },
                        Clock.System.now().plus(1.minutes),
                        it.credentialScheme as IsoMdocCredentialScheme,
                        it.subjectPublicKey,
                        OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                    )
                }
            }
        }
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val credentialEndpointPath = "/credential"
        val nonceEndpointPath = "/nonce"
        val parEndpointPath = "/par"
        val userInfoEndpointPath = "/userinfo"
        val introspectionEndpointPath = "/introspection"
        val challengeEndpointPath = "/challenge"
        val issuerPublicContext = "https://issuer.example.com"
        val authServerPublicContext = "https://auth.example.com"
        // TODO Re-test with JWT tokens (Problem when using token exchange: Validate DPoP for subject token on backend)
        // val tokenService = TokenService.jwt(issueRefreshTokens = true)
        val tokenService = TokenService.bearer(issueRefreshTokens = true)
        val externalAuthorizationServer = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            publicContext = authServerPublicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            userInfoEndpointPath = userInfoEndpointPath,
            introspectionEndpointPath = introspectionEndpointPath,
            challengeEndpointPath = challengeEndpointPath,
            clientAuthenticationService = AttestationBasedClientAuthenticationService(
                issuerIdentifier = if (validatePopAudience) authServerPublicContext else null,
            ),
            tokenService = tokenService,
        )
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        lateinit var openId4VciServer: OpenId4VciServer
        val mockEngine = MockEngine { request ->
            when {
                request.url.toString().startsWith(issuerPublicContext) &&
                        request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.CredentialIssuer ->
                    respond(openId4VciServer.metadataHttpResponse(request.headers[HttpHeaders.Accept]).getOrThrow())

                request.url.toString().startsWith(authServerPublicContext) &&
                        request.url.rawSegments.drop(1) == OpenIdConstants.WellKnownPaths.OauthAuthorizationServer ->
                    respond(externalAuthorizationServer.metadata().toHttpResponse())

                request.url.toString() == "$authServerPublicContext$parEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters =
                        RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                    externalAuthorizationServer.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString().startsWith("$authServerPublicContext$authorizationEndpointPath") -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: RequestParameters =
                        if (requestBody.isEmpty()) RequestParametersSerializer.decodeFormParameters(queryParameters)
                        else RequestParametersSerializer.decodeFormParameters(requestBody.toFormParameters())
                    externalAuthorizationServer.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$tokenEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromFormUrlEncoded<TokenRequestParameters>()
                    externalAuthorizationServer.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$userInfoEndpointPath" -> {
                    val authn = request.headers[HttpHeaders.Authorization]
                    externalAuthorizationServer.userInfoWithDpopNonce(authn!!, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondResourceServerError(it, authn) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$introspectionEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params = requestBody.decodeFromFormUrlEncoded<TokenIntrospectionRequest>()
                    externalAuthorizationServer.tokenIntrospection(params, request.toRequestInfo()).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$issuerPublicContext$nonceEndpointPath" -> {
                    respond(openId4VciServer.nonceWithDpopNonce().getOrThrow().toHttpResponse())
                }

                request.url.toString() == "$authServerPublicContext$challengeEndpointPath" -> {
                    externalAuthorizationServer.attestationChallenge().getOrThrow().shouldNotBeNull()
                        .let { respond(it.toHttpResponse()) }
                }

                request.url.toString() == "$issuerPublicContext$credentialEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = joseCompliantSerializer.decodeFromString<CredentialRequestParameters>(requestBody)
                    openId4VciServer.credential(
                        authorizationHeader = authn,
                        params = OpenId4VciClient.CredentialRequest.Plain(params),
                        credentialDataProvider = credentialDataProvider,
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = { respond(it.toHttpResponse()) },
                        onFailure = { respondResourceServerError(it, authn) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url}") }
            }
        }
        val walletClientId = "https://example.com/rp"
        openId4VciServer = OpenId4VciServer(
            authorizationService = RemoteOAuth2AuthorizationServerAdapter(
                publicContext = authServerPublicContext,
                httpClient = HttpClient(mockEngine),
                internalTokenVerificationService = tokenService.verification,
                oauth2Client = OAuth2Client(clientId = issuerPublicContext),
                clientAttestation = ClientAttestation(issuerClientAuthKeyMaterial) {
                    catching {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = issuerPublicContext,
                            clientKey = issuerClientAuthKeyMaterial.jsonWebKey
                        )
                    }
                },
            ),
            issuer = issuer,
            credentialSchemes = AttributeIndex.schemeSet,
            publicContext = issuerPublicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
        )
        return Context(
            credentialKeyMaterial = credentialKeyMaterial,
            walletClientAuthKeyMaterial = walletClientAuthKeyMaterial,
            mockEngine = mockEngine,
            issuerPublicContext = issuerPublicContext,
            issuerClientAuthKeyMaterial = issuerClientAuthKeyMaterial,
            openId4VciServer = openId4VciServer,
            externalAuthorizationServer = externalAuthorizationServer,
            client = OpenId4VciKtorClient(
                httpClient = HttpClient(mockEngine),
                oauth2Client = OAuth2Client(clientId = walletClientId),
                vciClient = OpenId4VciClient(keyMaterial = credentialKeyMaterial),
                clientAttestation = ClientAttestation(walletClientAuthKeyMaterial) {
                    catching {
                        BuildClientAttestationJwt(
                            SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                            clientId = walletClientId,
                            clientKey = walletClientAuthKeyMaterial.jsonWebKey
                        )
                    }
                },
            )
        )
    }

    test("loadEuPidCredentialSdJwt") {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidSdJwtDataElements.FAMILY_NAME
        val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
        with(setup(euPidSdJwtScheme, SD_JWT, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: CredentialRenewalInfo? = null
            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata(issuerPublicContext).getOrThrow()
            // Pick the EuPID SD-JWT credential configuration; other SD-JWT schemes may also be registered.
            val selectedCredential = credentialIdentifierInfos
                .first {
                    (it.supportedCredentialFormat as? SupportedCredentialFormatSdJwt)?.sdJwtVcType ==
                            euPidSdJwtScheme.sdJwtType
                }

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

    test("WIA PoP audience matches AS issuer for auth code and refresh token flows") {
        // The AS enforces that aud in the WIA PoP equals its own issuer identifier (authServerPublicContext),
        // not the credential issuer URL (issuerPublicContext). Without the fix, both token calls send
        // aud = issuerPublicContext and the AS rejects them with InvalidClient.
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidSdJwtDataElements.FAMILY_NAME
        val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
        with(
            setup(
                euPidSdJwtScheme,
                SD_JWT,
                mapOf(expectedAttributeName to expectedAttributeValue),
                validatePopAudience = true
            )
        ) {
            var refreshTokenStore: CredentialRenewalInfo? = null
            val credentialIdentifierInfos = client.loadCredentialMetadata(issuerPublicContext).getOrThrow()
            val selectedCredential = credentialIdentifierInfos
                .first {
                    (it.supportedCredentialFormat as? SupportedCredentialFormatSdJwt)?.sdJwtVcType ==
                            euPidSdJwtScheme.sdJwtType
                }

            client.startProvisioningWithAuthRequestReturningResult(
                credentialIssuerUrl = issuerPublicContext,
                credentialIdentifierInfo = selectedCredential,
            ).getOrThrow().also {
                val httpClient = HttpClient(mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it.url).headers[HttpHeaders.Location]
                // Without fix: aud = issuerPublicContext → AS rejects with InvalidClient (aud mismatch)
                // With fix: aud = authServerPublicContext → AS accepts
                client.resumeWithAuthCode(authCode!!, it.context).getOrThrow().also { result ->
                    refreshTokenStore = result.refreshToken!!
                    result.verifySdJwtCredential(
                        expectedAttributeName,
                        expectedAttributeValue,
                        credentialKeyMaterial.publicKey
                    )
                }
            }

            refreshTokenStore.shouldNotBeNull()
            // Without fix: aud = issuerPublicContext → AS rejects with InvalidClient (aud mismatch)
            // With fix: aud = authServerPublicContext → AS accepts
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                it.verifySdJwtCredential(expectedAttributeName, expectedAttributeValue, credentialKeyMaterial.publicKey)
            }
        }
    }

    test("loadEuPidCredentialIsoWithOffer") {
        val expectedAttributeValue = uuid4().toString()
        val expectedAttributeName = EuPidDataElements.GIVEN_NAME
        val euPidScheme = AttributeIndex.resolveIdentifier(EU_PID_DOCTYPE, ISO_MDOC)
        with(setup(euPidScheme, ISO_MDOC, mapOf(expectedAttributeName to expectedAttributeValue))) {
            var refreshTokenStore: CredentialRenewalInfo? = null
            // Load credential identifier infos from Issuing service
            val credentialIdentifierInfos = client.loadCredentialMetadata(issuerPublicContext).getOrThrow()
            // Pick the EuPID ISO mdoc credential configuration; other ISO schemes may also be registered.
            val selectedCredential = credentialIdentifierInfos
                .first {
                    (it.supportedCredentialFormat as? SupportedCredentialFormatIsoMdoc)?.docType ==
                            euPidScheme.isoDocType
                }

            val offer = externalAuthorizationServer.offerWithPreAuthnForUserForSchemes(
                user = dummyUser(),
                credentialIssuer = openId4VciServer.metadata.credentialIssuer,
                schemes = setOf(euPidScheme to ISO_MDOC),
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
