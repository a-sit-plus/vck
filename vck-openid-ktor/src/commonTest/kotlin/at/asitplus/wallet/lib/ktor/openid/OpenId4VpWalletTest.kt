package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.*
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidvci.*
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.AnnotationSpec
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
import kotlin.time.Duration.Companion.minutes

class OpenId4VpWalletTest : AnnotationSpec() {

    lateinit var countdownLatch: Mutex
    lateinit var keyMaterial: KeyMaterial
    lateinit var cryptoService: CryptoService
    lateinit var holderAgent: HolderAgent

    @BeforeEach
    fun beforeEach() {
        countdownLatch = Mutex(true)
        keyMaterial = EphemeralKeyWithoutCert()
        cryptoService = DefaultCryptoService(keyMaterial)
        holderAgent = HolderAgent(keyMaterial)
    }

    @Test
    fun presentEuPidCredential() = runTest {
        val expectedScheme = EuPidScheme
        val expectedRepresentation = ConstantIndex.CredentialRepresentation.SD_JWT
        val expectedAttributes = mapOf(
            EuPidScheme.Attributes.FAMILY_NAME to Random.nextBytes(32).encodeToString(Base16)
        )
        val clientId = uuid4().toString()
        val requestEndpointPath = "/request/${uuid4()}"
        val requestOptionsCredential = OidcSiopVerifier.RequestOptionsCredential(
            credentialScheme = expectedScheme,
            representation = expectedRepresentation,
            requestedAttributes = expectedAttributes.keys.toList()
        )
        val mockEngine = setupRelyingPartyService(requestEndpointPath, clientId, requestOptionsCredential) {
            verifyReceivedAttributes(expectedAttributes, it)
        }
        val urlToSendToWallet = buildUrlWithRequestByReference(clientId, requestEndpointPath)

        issueAndStoreCredentials(expectedAttributes, expectedScheme)

        val wallet = OpenId4VpWallet(
            openUrlExternally = {},
            engine = mockEngine,
            cryptoService = cryptoService,
            holderAgent = holderAgent,
        )

        val requestParametersFrom = wallet.parseAuthenticationRequestParameters(urlToSendToWallet).getOrThrow()
        // posts the response to the mock RP, which calls the block on setupRelyingPartyService, which unlocks the latch
        wallet.startPresentation(requestParametersFrom).apply {
            this.isSuccess shouldBe true
        }

        assertPresentation(countdownLatch)
    }

    private fun buildUrlWithRequestByReference(clientId: String, requestEndpointPath: String): String {
        val urlToSendToWallet = URLBuilder("http://wallet.example.com/").apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", "http://rp.example.com$requestEndpointPath")
        }.buildString()
        return urlToSendToWallet
    }

    private suspend fun issueAndStoreCredentials(
        expectedAttributes: Map<String, String>,
        expectedScheme: EuPidScheme,
    ) {
        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                CredentialToBeIssued.VcSd(
                    claims = expectedAttributes.map { ClaimToBeIssued(it.key, it.value) },
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = expectedScheme,
                    subjectPublicKey = keyMaterial.publicKey
                )
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
    }

    private fun verifyReceivedAttributes(
        expectedAttributes: Map<String, String>,
        result: OidcSiopVerifier.AuthnResponseResult,
    ) {
        when (result) {
            is OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt ->
                if (expectedAttributes.all { attribute ->
                        result.disclosures.toList().any { it.matchesAttribute(attribute) }
                    }) {
                    countdownLatch.unlock()
                }

            else -> {}
        }
    }

    private fun SelectiveDisclosureItem.matchesAttribute(attribute: Map.Entry<String, String>): Boolean =
        claimName == attribute.key && claimValue.jsonPrimitive.content == attribute.value

    // If the countdownLatch has been unlocked, the correct credential has been posted to the RP, and we're done!
    private suspend fun assertPresentation(countdownLatch: Mutex) {
        withContext(Dispatchers.Default.limitedParallelism(1)) {
            withTimeout(5000) {
                countdownLatch.lock()
            }
        }
    }

    /**
     * Setup the mock relying party service, for getting requests (referenced by `request_uri`) and to decode posted
     * authentication responses
     */
    private suspend fun setupRelyingPartyService(
        requestEndpointPath: String,
        clientId: String,
        requestOptionsCredential: OidcSiopVerifier.RequestOptionsCredential,
        validate: (OidcSiopVerifier.AuthnResponseResult) -> Unit,
    ): HttpClientEngine {
        val verifier = OidcSiopVerifier(
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.PreRegistered(clientId),
        )
        val responseEndpointPath = "/response"
        val jar = verifier.createAuthnRequestAsSignedRequestObject(
            requestOptions = OidcSiopVerifier.RequestOptions(
                credentials = setOf(requestOptionsCredential),
                responseMode = OpenIdConstants.ResponseMode.DirectPost,
                responseUrl = responseEndpointPath,
            )
        ).getOrThrow()

        return MockEngine { request ->
            when {
                request.url.fullPath == requestEndpointPath -> respond(
                    vckJsonSerializer.encodeToString(jar.serialize()),
                )

                request.url.fullPath.startsWith(responseEndpointPath) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val authnRequest: AuthenticationResponseParameters =
                        if (requestBody.isEmpty()) queryParameters.decodeFromUrlQuery()
                        else requestBody.decodeFromPostBody()
                    val result = verifier.validateAuthnResponse(authnRequest)
                    validate(result)
                    respondOk()
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
    }
}