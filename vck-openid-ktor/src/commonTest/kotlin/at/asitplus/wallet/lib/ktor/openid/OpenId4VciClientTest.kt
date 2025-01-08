package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.lib.oidvci.*
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random

class OpenId4VciClientTest : AnnotationSpec() {

    lateinit var countdownLatch: Mutex
    lateinit var keyMaterial: KeyMaterial
    lateinit var cryptoService: CryptoService

    @BeforeEach
    fun beforeEach() {
        countdownLatch = Mutex(true)
        keyMaterial = EphemeralKeyWithoutCert()
        cryptoService = DefaultCryptoService(keyMaterial)
    }

    @Test
    fun loadEuPidCredentialSdJwt() = runTest {
        val expectedAttributes = mapOf(
            EuPidScheme.Attributes.FAMILY_NAME to Random.nextBytes(32).encodeToString(Base16)
        )
        val (mockEngine, credentialIssuer) = setupIssuingService(EuPidScheme, SD_JWT, expectedAttributes)
        val subjectCredentialStore = assertAttributeStore(EuPidScheme, expectedAttributes)
        val holderAgent = HolderAgent(keyMaterial, subjectCredentialStore)
        val client: OpenId4VciClient = setupClient(mockEngine, holderAgent)

        // Load credential identifier infos from Issuing service
        val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
        // just pick the first credential in SD-JWT that is available
        val selectedCredential = credentialIdentifierInfos
            .first { it.supportedCredentialFormat.format == CredentialFormatEnum.VC_SD_JWT }
        // client will call clientBrowser.openUrlExternally
        client.startProvisioningWithAuthRequest(
            credentialIssuer = "http://localhost",
            credentialIdentifierInfo = selectedCredential,
            requestedAttributes = setOf()
        )

        assertCorrectCredentialIssued()
    }

    @Test
    fun loadEuPidCredentialIsoWithOffer() = runTest {
        val expectedAttributes = mapOf(
            EuPidScheme.Attributes.GIVEN_NAME to Random.nextBytes(32).encodeToString(Base16)
        )
        val (mockEngine, credentialIssuer) = setupIssuingService(EuPidScheme, ISO_MDOC, expectedAttributes)
        val subjectCredentialStore = assertAttributeStore(EuPidScheme, expectedAttributes)
        val holderAgent = HolderAgent(keyMaterial, subjectCredentialStore)
        val client: OpenId4VciClient = setupClient(mockEngine, holderAgent)

        // Load credential identifier infos from Issuing service
        val credentialIdentifierInfos = client.loadCredentialMetadata("http://localhost").getOrThrow()
        // just pick the first credential in MSO_MDOC that is available
        val selectedCredential = credentialIdentifierInfos
            .first { it.supportedCredentialFormat.format == CredentialFormatEnum.MSO_MDOC }

        val offer = credentialIssuer.credentialOfferWithPreAuthnForUser(dummyUser())
        client.loadCredentialWithOffer(offer,selectedCredential, null, null).apply {
            this.isSuccess shouldBe true
        }
        assertCorrectCredentialIssued()
    }

    private fun setupClient(
        mockEngine: HttpClientEngine,
        holderAgent: HolderAgent,
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
        client = OpenId4VciClient(
            openUrlExternally = { clientBrowser.openUrlExternally(it) },
            engine = mockEngine,
            storeProvisioningContext = { provisioningContextStore = it },
            loadProvisioningContext = { provisioningContextStore },
            loadClientAttestationJwt = { "" },
            cryptoService = cryptoService,
            holderAgent = holderAgent,
            redirectUrl = "http://localhost/mock/",
            clientId = "some client id"
        )
        return client
    }

    private fun assertAttributeStore(
        expectedScheme: ConstantIndex.CredentialScheme,
        expectedAttributes: Map<String, String>,
    ): SubjectCredentialStore = object : SubjectCredentialStore {
        override suspend fun storeCredential(
            vc: VerifiableCredentialJws,
            vcSerialized: String,
            scheme: ConstantIndex.CredentialScheme,
        ) = SubjectCredentialStore.StoreEntry.Vc(vcSerialized, vc, scheme.schemaUri)

        override suspend fun storeCredential(
            vc: VerifiableCredentialSdJwt,
            vcSerialized: String,
            disclosures: Map<String, SelectiveDisclosureItem?>,
            scheme: ConstantIndex.CredentialScheme,
        ) = SubjectCredentialStore.StoreEntry.SdJwt(vcSerialized, vc, disclosures, scheme.schemaUri).also {
            if (expectedAttributes.all { attribute ->
                    disclosures.values.filterNotNull()
                        .any { it.claimName == attribute.key && it.claimValue.jsonPrimitive.content == attribute.value }
                } && scheme == expectedScheme) {
                countdownLatch.unlock()
            }
        }

        override suspend fun storeCredential(issuerSigned: IssuerSigned, scheme: ConstantIndex.CredentialScheme) =
            SubjectCredentialStore.StoreEntry.Iso(issuerSigned, scheme.schemaUri)

        override suspend fun getCredentials(credentialSchemes: Collection<ConstantIndex.CredentialScheme>?): KmmResult<List<SubjectCredentialStore.StoreEntry>> =
            KmmResult.success(listOf())
    }

    // Mocks the Issuing Service, which will be called by [OpenId4VciClient]
    private fun setupIssuingService(
        scheme: ConstantIndex.CredentialScheme,
        representationToIssue: ConstantIndex.CredentialRepresentation,
        attributesToIssue: Map<String, String>,
    ): Pair<HttpClientEngine, CredentialIssuer> {
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
                CredentialToBeIssued.VcSd(
                    attributesToIssue.map { ClaimToBeIssued(it.key, it.value) },
                    Clock.System.now(),
                    credentialScheme,
                    subjectPublicKey
                )
            }
        }
        val credentialSchemes = setOf(EuPidScheme)
        val authorizationEndpointPath = "/authorize"
        val tokenEndpointPath = "/token"
        val credentialEndpointPath = "/credential"
        val publicContext = "http://issuer.example.com"
        val authorizationService = SimpleAuthorizationService(
            strategy = CredentialAuthorizationServiceStrategy(
                dataProvider = dataProvider,
                credentialSchemes = credentialSchemes
            ),
            publicContext = publicContext,
            authorizationEndpointPath = authorizationEndpointPath,
            tokenEndpointPath = tokenEndpointPath,
        )
        val credentialIssuer = CredentialIssuer(
            authorizationService = authorizationService,
            issuer = IssuerAgent(),
            credentialSchemes = credentialSchemes,
            credentialProvider = credentialProvider,
            publicContext = publicContext,
            credentialEndpointPath = credentialEndpointPath,
        )

        return Pair(MockEngine { request ->
            when {
                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER -> respond(
                    vckJsonSerializer.encodeToString(credentialIssuer.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

                request.url.fullPath == OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION -> respond(
                    vckJsonSerializer.encodeToString(authorizationService.metadata),
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )

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
                    val result = authorizationService.token(params).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )
                }

                request.url.fullPath.startsWith(credentialEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val authorizationHeader = request.headers[HttpHeaders.Authorization].shouldNotBeNull()
                    val params = CredentialRequestParameters.deserialize(requestBody).getOrThrow()
                    val accessToken = authorizationHeader.removePrefix("bearer ").removePrefix("Bearer ")
                    val result = credentialIssuer.credential(accessToken, params).getOrThrow()
                    respond(
                        vckJsonSerializer.encodeToString(result),
                        headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    )

                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }, credentialIssuer)
    }

    private fun dummyUser(): OidcUserInfoExtended = OidcUserInfoExtended.deserialize("{\"sub\": \"foo\"}").getOrThrow()

    // If the countdownLatch has been unlocked, the correct credential has been stored, and we're done!
    private suspend fun assertCorrectCredentialIssued() {
        withContext(Dispatchers.Default.limitedParallelism(1)) {
            withTimeout(5000) {
                countdownLatch.lock()
            }
        }
    }
}