package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.Iso
import at.asitplus.wallet.lib.agent.CredentialToBeIssued.VcSd
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.TokenService
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.CredentialIssuer
import at.asitplus.wallet.lib.oidvci.CredentialIssuerDataProvider
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.OAuth2DataProvider
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.engine.mock.respondRedirect
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.*
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.fullPath
import io.ktor.http.headersOf
import io.ktor.util.toMap
import kotlinx.coroutines.test.runTest
import kotlinx.datetime.Clock
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random

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
            runTest {
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
        }

        test("loadEuPidCredentialIsoWithOffer") {
            runTest {
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
    }

    private suspend fun verifySdJwtCredential(
        success: CredentialIssuanceResult.Success,
        expectedFamilyName: String,
    ) {
        success.credentials.shouldBeSingleton().also {
            it.first().shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>().also {
                it.scheme shouldBe EuPidScheme
                val sdJwt =
                    Validator().verifySdJwt(
                        SdJwtSigned.parse(it.vcSdJwt)!!,
                        credentialKeyMaterial.publicKey
                    )
                sdJwt.shouldBeInstanceOf<VerifyCredentialResult.SuccessSdJwt>()
                sdJwt.disclosures.values.any { it.claimName == EuPidScheme.Attributes.FAMILY_NAME && it.claimValue.jsonPrimitive.content == expectedFamilyName }
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
        val dataProvider = OAuth2DataProvider { _, _ -> dummyUser() }
        val credentialProvider =
            CredentialIssuerDataProvider { _, subjectPublicKey: CryptoPublicKey, credentialScheme, representation, _ ->
                catching {
                    require(credentialScheme == scheme)
                    require(representation == representation)
                    var digestId = 0u
                    when (representation) {
                        PLAIN_JWT -> TODO()
                        SD_JWT -> VcSd(
                            attributes.map { ClaimToBeIssued(it.key, it.value) },
                            Clock.System.now(),
                            credentialScheme,
                            subjectPublicKey
                        )

                        ISO_MDOC -> Iso(
                            attributes.map {
                                IssuerSignedItem(
                                    digestId++,
                                    Random.nextBytes(32),
                                    it.key,
                                    it.value
                                )
                            },
                            Clock.System.now(),
                            credentialScheme,
                            subjectPublicKey
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
            dataProvider = dataProvider,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            ),
            tokenService = TokenService.jwt(
                nonceService = DefaultNonceService(),
                keyMaterial = EphemeralKeyWithoutCert(),
                issueRefreshTokens = true
            ),
        )
        credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(EphemeralKeyWithSelfSignedCert()),
            credentialSchemes = credentialSchemes,
            credentialProvider = credentialProvider,
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
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER -> respond(
                    vckJsonSerializer.encodeToString<OAuth2AuthorizationServerMetadata>(authorizationService.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: AuthenticationRequestParameters =
                        requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    val result = authorizationService.par(
                        authnRequest,
                        request.headers["OAuth-Client-Attestation"],
                        request.headers["OAuth-Client-Attestation-PoP"]
                    ).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<PushedAuthenticationResponseParameters>(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: AuthenticationRequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery<AuthenticationRequestParameters>()
                        else requestBody.decodeFromPostBody<AuthenticationRequestParameters>()
                    val result = authorizationService.authorize(authnRequest).getOrThrow()
                    respondRedirect(result.url)
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody<TokenRequestParameters>()
                    val result = authorizationService.token(params, request.toRequestInfo()).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<TokenResponseParameters>(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    val result = credentialIssuer.nonce().getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<ClientNonceResponse>(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = CredentialRequestParameters.deserialize(requestBody).getOrThrow()
                    val result = credentialIssuer.credential(authn, params, request.toRequestInfo()).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString<CredentialResponseParameters>(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )

                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
        val clientId = "https://example.com/rp"
        client = OpenId4VciClient(
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
            signDpop = SignJwt(dpopKeyMaterial, JwsHeaderJwk()),
            dpopAlgorithm = dpopKeyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            oid4vciService = WalletService(
                clientId = clientId,
                keyMaterial = credentialKeyMaterial,
            ),
        )
    }

    private fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
        url = url.toString(),
        method = method,
        dpop = headers["DPoP"],
        clientAttestation = headers["OAuth-Client-Attestation"],
        clientAttestationPop = headers["OAuth-Client-Attestation-PoP"],
    )

    private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()
}
