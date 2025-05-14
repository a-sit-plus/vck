package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.Validator
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.ClientAuthenticationService
import at.asitplus.wallet.lib.oauth2.RequestInfo
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
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
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.respondError
import io.ktor.client.engine.mock.respondRedirect
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.get
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.fullPath
import io.ktor.http.headersOf
import io.ktor.util.toMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.datetime.Clock
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random

/**
 * Tests [OpenId4VciClient] by using the deprecated constructor parameters
 */
class DeprecatedOpenId4VciClientTest : FunSpec() {

    lateinit var countdownLatch: Mutex
    lateinit var credentialKeyMaterial: KeyMaterial
    lateinit var dpopKeyMaterial: KeyMaterial
    lateinit var clientAuthKeyMaterial: KeyMaterial
    lateinit var refreshTokenStore: RefreshTokenInfo

    init {
        beforeEach {
            countdownLatch = Mutex(true)
            credentialKeyMaterial = EphemeralKeyWithoutCert()
            dpopKeyMaterial = EphemeralKeyWithoutCert()
            clientAuthKeyMaterial = EphemeralKeyWithoutCert()
        }

        test("loadEuPidCredentialSdJwt") {
            runTest {
                val expectedFamilyName = uuid4().toString()
                val (client, credentialIssuer) = setup(
                    scheme = EuPidScheme,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributes = mapOf(
                        EuPidScheme.Attributes.FAMILY_NAME to expectedFamilyName
                    ),
                    storeCredential = {
                        it.shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>()
                        it.scheme shouldBe EuPidScheme
                        val sdJwt =
                            Validator().verifySdJwt(
                                SdJwtSigned.Companion.parse(it.vcSdJwt)!!,
                                credentialKeyMaterial.publicKey
                            )
                        sdJwt.shouldBeInstanceOf<Verifier.VerifyCredentialResult.SuccessSdJwt>()
                        sdJwt.disclosures.values.any { it.claimName == EuPidScheme.Attributes.FAMILY_NAME && it.claimValue.jsonPrimitive.content == expectedFamilyName }
                            .shouldBeTrue()
                        countdownLatch.unlock()
                    }
                )

                // Load credential identifier infos from Issuing service
                val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
                // just pick the first credential in SD-JWT that is available
                val selectedCredential = credentialIdentifierInfos
                    .first { it.supportedCredentialFormat.format == CredentialFormatEnum.DC_SD_JWT }
                // client will call clientBrowser.openUrlExternally
                client.startProvisioningWithAuthRequest(
                    credentialIssuerUrl = "http://localhost",
                    credentialIdentifierInfo = selectedCredential,
                ).apply {
                    this.isSuccess shouldBe true
                }
                assertCorrectCredentialIssued()

                countdownLatch = Mutex(true)
                refreshTokenStore.shouldNotBeNull()
                client.refreshCredential(refreshTokenStore).apply {
                    this.isSuccess shouldBe true
                }
                assertCorrectCredentialIssued()
            }
        }

        test("loadEuPidCredentialIsoWithOffer") {
            runTest {
                val expectedGivenName = uuid4().toString()
                val (client, credentialIssuer, authorizationService) = setup(
                    scheme = EuPidScheme,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    attributes = mapOf(
                        EuPidScheme.Attributes.GIVEN_NAME to expectedGivenName
                    ),
                    storeCredential = {
                        it.shouldBeInstanceOf<Holder.StoreCredentialInput.Iso>()
                        it.scheme shouldBe EuPidScheme
                        it.issuerSigned.namespaces?.values?.flatMap { it.entries }?.map { it.value }
                            ?.any { it.elementIdentifier == EuPidScheme.Attributes.GIVEN_NAME && it.elementValue == expectedGivenName }
                            ?.shouldNotBeNull()?.shouldBeTrue()
                        countdownLatch.unlock()
                    }
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
                client.loadCredentialWithOffer(offer, selectedCredential, null).apply {
                    this.isSuccess shouldBe true
                }
                assertCorrectCredentialIssued()

                countdownLatch = Mutex(true)
                refreshTokenStore.shouldNotBeNull()
                client.refreshCredential(refreshTokenStore).apply {
                    this.isSuccess shouldBe true
                }
                assertCorrectCredentialIssued()
            }
        }
    }

    private fun setup(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
        storeCredential: (suspend (Holder.StoreCredentialInput) -> Unit) = {},
    ): SetupResult {
        val (mockEngine, credentialIssuer, authorizationService) = setupIssuingService(
            scheme,
            representation,
            attributes
        )
        val client = setupClient(mockEngine, storeCredential)
        return SetupResult(client, credentialIssuer, authorizationService)
    }

    private fun setupClient(
        mockEngine: HttpClientEngine,
        storeCredential: (suspend (Holder.StoreCredentialInput) -> Unit),
    ): OpenId4VciClient {
        // This construction is needed to continue with client in the openUrlExternally callback
        var client: OpenId4VciClient? = null
        // Simulates the browser, handling authorization to get the authCode
        val clientBrowser = object {
            suspend fun openUrlExternally(it: String) {
                val httpClient = HttpClient(mockEngine) { followRedirects = false }
                val authCode = httpClient.get(it).headers[HttpHeaders.Location]
                client!!.resumeWithAuthCode(authCode!!)
            }
        }
        var provisioningContextStore: ProvisioningContext? = null
        val clientId = "https://example.com/rp"
        client = OpenId4VciClient(
            openUrlExternally = { clientBrowser.openUrlExternally(it) },
            engine = mockEngine,
            storeProvisioningContext = { provisioningContextStore = it },
            loadProvisioningContext = { provisioningContextStore },
            loadClientAttestationJwt = {
                BuildClientAttestationJwt(
                    SignJwt<JsonWebToken>(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
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
            storeCredential = storeCredential,
            storeRefreshToken = { refreshTokenStore = it }
        )
        return client
    }

    // Mocks the Issuing Service, which will be called by [OpenId4VciClient]
    private fun setupIssuingService(
        scheme: ConstantIndex.CredentialScheme,
        representationToIssue: ConstantIndex.CredentialRepresentation,
        attributesToIssue: Map<String, String>,
    ): Triple<HttpClientEngine, CredentialIssuer, SimpleAuthorizationService> {
        val dataProvider = object : OAuth2DataProvider {
            override suspend fun loadUserInfo(
                request: AuthenticationRequestParameters,
                code: String,
            ) = dummyUser()
        }
        val credentialProvider = object : CredentialIssuerDataProvider {
            override fun getCredential(
                userInfo: OidcUserInfoExtended,
                subjectPublicKey: CryptoPublicKey,
                credentialScheme: ConstantIndex.CredentialScheme,
                representation: ConstantIndex.CredentialRepresentation,
                claimNames: Collection<String>?,
            ): KmmResult<CredentialToBeIssued> = catching {
                require(credentialScheme == scheme)
                require(representation == representationToIssue)
                var digestId = 0u
                when (representation) {
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT -> TODO()
                    ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialToBeIssued.VcSd(
                        attributesToIssue.map { ClaimToBeIssued(it.key, it.value) },
                        Clock.System.now(),
                        credentialScheme,
                        subjectPublicKey
                    )

                    ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialToBeIssued.Iso(
                        attributesToIssue.map {
                            IssuerSignedItem(
                                digestId++,
                                Random.Default.nextBytes(32),
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
        val authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(credentialSchemes),
            dataProvider = dataProvider,
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
            pushedAuthorizationRequestEndpointPath = parEndpointPath,
            clientAuthenticationService = ClientAuthenticationService(
                enforceClientAuthentication = true,
            ),
            tokenService = TokenService.Companion.jwt(
                nonceService = DefaultNonceService(),
                keyMaterial = EphemeralKeyWithoutCert(),
                issueRefreshTokens = true
            ),
        )
        val credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(EphemeralKeyWithSelfSignedCert()),
            credentialSchemes = credentialSchemes,
            credentialProvider = credentialProvider,
            publicContext = publicContext,
            credentialEndpointPath = credentialEndpointPath,
            nonceEndpointPath = nonceEndpointPath,
        )

        return Triple(MockEngine.Companion { request ->
            when {
                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER -> respond(
                    vckJsonSerializer.encodeToString(credentialIssuer.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION -> respond(
                    vckJsonSerializer.encodeToString(authorizationService.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER -> respond(
                    vckJsonSerializer.encodeToString(authorizationService.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath.startsWith(parEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authnRequest: AuthenticationRequestParameters = requestBody.decodeFromPostBody()
                    val result = authorizationService.par(
                        authnRequest,
                        request.headers["OAuth-Client-Attestation"],
                        request.headers["OAuth-Client-Attestation-PoP"]
                    ).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(authorizationEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: AuthenticationRequestParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    val result = authorizationService.authorize(authnRequest).getOrThrow()
                    respondRedirect(result.url)
                }

                request.url.fullPath.startsWith(tokenEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val params: TokenRequestParameters = requestBody.decodeFromPostBody()
                    val result = authorizationService.token(params, request.toRequestInfo()).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(nonceEndpointPath) -> {
                    val result = credentialIssuer.nonce().getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authn = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = CredentialRequestParameters.Companion.deserialize(requestBody).getOrThrow()
                    val result = credentialIssuer.credential(authn, params, request.toRequestInfo()).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )

                }

                else -> respondError(HttpStatusCode.Companion.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }, credentialIssuer, authorizationService)
    }

    private fun HttpRequestData.toRequestInfo(): RequestInfo = RequestInfo(
        url = url.toString(),
        method = method,
        dpop = headers["DPoP"],
        clientAttestation = headers["OAuth-Client-Attestation"],
        clientAttestationPop = headers["OAuth-Client-Attestation-PoP"],
    )

    private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.Companion.deserialize("{\"sub\": \"foo\"}").getOrThrow()

    // If the countdownLatch has been unlocked, the correct credential has been stored, and we're done!
    private suspend fun assertCorrectCredentialIssued() {
        withContext(Dispatchers.Default.limitedParallelism(1)) {
            withTimeout(5000) {
                countdownLatch.lock()
            }
        }
    }
}
data class SetupResult(
    val openId4VciClient: OpenId4VciClient,
    val credentialIssuer: CredentialIssuer,
    val authorizationService: SimpleAuthorizationService,
)