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
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.RequestParameters
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
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
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
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
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
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Clock

/**
 * Tests [OpenId4VciClient] against [CredentialIssuer] with our own internal [SimpleAuthorizationService].
 */
class OpenId4VciClientTest : FunSpec() {

    lateinit var credentialKeyMaterial: KeyMaterial
    lateinit var dpopKeyMaterial: KeyMaterial
    lateinit var clientAuthKeyMaterial: KeyMaterial
    lateinit var refreshTokenStore: RefreshTokenInfo

    lateinit var mockEngine: MockEngine
    lateinit var credentialIssuer: CredentialIssuer
    lateinit var authorizationService: SimpleAuthorizationService
    lateinit var client: OpenId4VciClient

    init {
        beforeEach {
            credentialKeyMaterial = EphemeralKeyWithoutCert()
            dpopKeyMaterial = EphemeralKeyWithoutCert()
            clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        }

        test("loadEuPidCredentialSdJwt") {
            val expectedFamilyName = uuid4().toString()
            setup(
                scheme = EuPidScheme,
                representation = SD_JWT,
                attributes = mapOf(EuPidScheme.Attributes.FAMILY_NAME to expectedFamilyName),
            )

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
                        claims = attributes.map { ClaimToBeIssued(it.key, it.value) },
                        expiration = Clock.System.now(),
                        scheme = it.credentialScheme,
                        subjectPublicKey = it.subjectPublicKey,
                        userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
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
        val publicContext = "https://issuer.example.com"
        authorizationService = SimpleAuthorizationService(
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
        credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = issuer,
            credentialSchemes = credentialSchemes,
            publicContext = publicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
        )
        mockEngine = MockEngine { request ->
            when {
                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER -> respond(
                    vckJsonSerializer.encodeToString<IssuerMetadata>(credentialIssuer.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata()),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: RequestParameters = requestBody.decodeFromPostBody()
                    authorizationService.par(authnRequest, request.toRequestInfo()).fold(
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<PushedAuthenticationResponseParameters>(it),
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            )
                        },
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
                        onSuccess = {
                            respond(
                                vckJsonSerializer.encodeToString<TokenResponseParameters>(it),
                                headers = headers {
                                    append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                                }
                            )
                        },
                        onFailure = { respondOAuth2Error(it) }
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    val result = credentialIssuer.nonceWithDpopNonce().getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<ClientNonceResponse>(result.response),
                        headers = headers {
                            append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                            result.dpopNonce?.let { set(HttpHeaders.DPoPNonce, it) }
                        }
                    )
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
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
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
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
    }

    private fun MockRequestHandleScope.respondOAuth2Error(throwable: Throwable): HttpResponseData = respond(
        vckJsonSerializer.encodeToString<OAuth2Error>(throwable.toOAuth2Error(null)),
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
