package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.Iso
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.VcSd
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialDataProviderFun
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.openid.toOAuth2Error
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] that uses [RemoteOAuth2AuthorizationServerAdapter]
 * to simulate an external OAuth2.0 Authorization Server (which is still our own internal [SimpleAuthorizationService]).
 */
class OpenId4VciClientExternalAuthorizationServerTest : FunSpec() {

    lateinit var credentialKeyMaterial: KeyMaterial
    lateinit var walletDpopKeyMaterial: KeyMaterial
    lateinit var walletClientAuthKeyMaterial: KeyMaterial
    lateinit var refreshTokenStore: RefreshTokenInfo

    lateinit var mockEngine: MockEngine
    lateinit var credentialIssuer: CredentialIssuer
    lateinit var externalAuthorizationServer: SimpleAuthorizationService
    lateinit var client: OpenId4VciClient

    lateinit var issuerDpopKeyMaterial: KeyMaterial
    lateinit var issuerClientAuthKeyMaterial: KeyMaterial
    lateinit var issuerPublicContext: String

    init {
        beforeEach {
            credentialKeyMaterial = EphemeralKeyWithoutCert()
            walletDpopKeyMaterial = EphemeralKeyWithoutCert()
            walletClientAuthKeyMaterial = EphemeralKeyWithoutCert()
            issuerDpopKeyMaterial = EphemeralKeyWithoutCert()
            issuerClientAuthKeyMaterial = EphemeralKeyWithoutCert()
        }

        test("loadEuPidCredentialSdJwt") {

            val expectedFamilyName = uuid4().toString()
            setup(
                scheme = EuPidScheme,
                representation = SD_JWT,
                attributes = mapOf(EuPidScheme.Attributes.FAMILY_NAME to expectedFamilyName),
            )

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
                    verifySdJwtCredential(it, expectedFamilyName)
                }
            }

            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                verifySdJwtCredential(it, expectedFamilyName)
            }

        }

        test("loadEuPidCredentialIsoWithOffer") {
            val expectedGivenName = uuid4().toString()
            setup(
                scheme = EuPidScheme,
                representation = ISO_MDOC,
                attributes = mapOf(
                    EuPidScheme.Attributes.GIVEN_NAME to expectedGivenName
                )
            )

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
                    verifyIsoMdocCredential(it, expectedGivenName)
                }
            }
            refreshTokenStore.shouldNotBeNull()
            client.refreshCredentialReturningResult(refreshTokenStore).getOrThrow().also {
                verifyIsoMdocCredential(it, expectedGivenName)
            }

        }
    }

    private suspend fun verifySdJwtCredential(
        success: CredentialIssuanceResult.Success,
        expectedFamilyName: String,
    ) {
        success.credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>().also {
                it.scheme shouldBe EuPidScheme
                ValidatorSdJwt().verifySdJwt(it.signedSdJwtVc, credentialKeyMaterial.publicKey)
                    .shouldBeInstanceOf<VerifyCredentialResult.SuccessSdJwt>()
                    .disclosures.values.any {
                        it.claimName == EuPidScheme.Attributes.FAMILY_NAME &&
                                it.claimValue.jsonPrimitive.content == expectedFamilyName
                    }
                    .shouldBeTrue()
            }
        }
    }

    private fun verifyIsoMdocCredential(
        success: CredentialIssuanceResult.Success,
        expectedGivenName: String,
    ) {
        success.credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.Iso>().also {
                it.scheme shouldBe EuPidScheme
                it.issuerSigned.namespaces?.values?.flatMap { it.entries }?.map { it.value }
                    ?.any { it.elementIdentifier == EuPidScheme.Attributes.GIVEN_NAME && it.elementValue == expectedGivenName }
                    ?.shouldNotBeNull()?.shouldBeTrue()
            }
        }
    }

    private fun setup(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
    ) {
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
        issuerPublicContext = "https://issuer.example.com"
        val authServerPublicContext = "https://auth.example.com"
        val tokenService = TokenService.jwt(
            issueRefreshTokens = true
        )
        externalAuthorizationServer = SimpleAuthorizationService(
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

        mockEngine = MockEngine { request ->
            when {
                request.url.toString() == "$issuerPublicContext${PATH_WELL_KNOWN_CREDENTIAL_ISSUER}" -> respond(
                    vckJsonSerializer.encodeToString<IssuerMetadata>(credentialIssuer.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == "$authServerPublicContext${PATH_WELL_KNOWN_OPENID_CONFIGURATION}" -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(externalAuthorizationServer.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == "$authServerPublicContext${PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER}" -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(externalAuthorizationServer.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.toString() == "$authServerPublicContext$parEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: AuthenticationRequestParameters =
                        requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    externalAuthorizationServer.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<PushedAuthenticationResponseParameters>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString().startsWith("$authServerPublicContext$authorizationEndpointPath") -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: AuthenticationRequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery<AuthenticationRequestParameters>()
                        else requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    externalAuthorizationServer.authorize(authnRequest) { catching { dummyUser() } }.fold(
                        onSuccess = { respondRedirect(it.url) },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$tokenEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    externalAuthorizationServer.token(params, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString(it),
                                headers = headers {
                                    append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                                }
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.toString() == "$authServerPublicContext$userInfoEndpointPath" -> {
                    val authn = request.headers[HttpHeaders.Authorization]
                    externalAuthorizationServer.userInfo(authn!!, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<JsonObject>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )

                }

                request.url.toString() == "$authServerPublicContext$introspectionEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params = requestBody.decodeFromPostBody<TokenIntrospectionRequest>()
                    externalAuthorizationServer.tokenIntrospection(params, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<TokenIntrospectionResponse>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )

                }

                request.url.toString() == "$issuerPublicContext$nonceEndpointPath" -> {
                    val result = credentialIssuer.nonceWithDpopNonce().getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<ClientNonceResponse>(result.response),
                        headers = headers {
                            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            result.dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) }
                        }
                    )
                }

                request.url.toString() == "$issuerPublicContext$credentialEndpointPath" -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = vckJsonSerializer.decodeFromString<CredentialRequestParameters>(requestBody)
                    credentialIssuer.credential(
                        authorizationHeader = authn,
                        params = params,
                        credentialDataProvider = credentialDataProvider,
                        request = request.toRequestInfo(),
                    ).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<CredentialResponseParameters>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url}") }
            }
        }
        val walletClientId = "https://example.com/rp"
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
    }

    private fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData = respond(
        vckJsonSerializer.encodeToString(throwable.toOAuth2Error(null)),
        headers = headers {
            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            (throwable as? OAuth2Exception.UseDpopNonce)?.dpopNonce
                ?.let { append(HttpHeaders.DPoPNonce, it) }
        },
        status = HttpStatusCode.BadRequest
    ).also { Napier.w("Server error: ${throwable.message}", throwable) }

    private fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
        url = url.toString(),
        method = method,
        dpop = headers["DPoP"],
        clientAttestation = headers["OAuth-Client-Attestation"],
        clientAttestationPop = headers["OAuth-Client-Attestation-PoP"],
    )

    private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
}
