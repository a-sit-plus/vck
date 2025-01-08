package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.*
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidvci.*
import com.benasher44.uuid.uuid4
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
import kotlin.time.Duration.Companion.minutes

class OpenId4VpWalletTest : AnnotationSpec() {

    @Test
    fun presentEuPidCredential() = runTest {
        val countdownLatch = Mutex(true)
        val expectedFamilyName = Random.nextBytes(32).encodeToString(Base16)
        val clientId = "clientId"
        val requestEndpointPath = "/request/${uuid4()}"
        val mockEngine = setupRelyingPartyService(requestEndpointPath, clientId) { result ->
            if (result.disclosures.firstOrNull {
                    it.claimName == EuPidScheme.Attributes.FAMILY_NAME && it.claimValue.jsonPrimitive.content == expectedFamilyName
                } != null) {
                countdownLatch.unlock()
            }
        }
        val urlToSendToWallet = URLBuilder("http://wallet.example.com/").apply {
            parameters.append("client_id", clientId)
            parameters.append("request_uri", "http://rp.example.com$requestEndpointPath")
        }.buildString()

        val keyMaterial = EphemeralKeyWithoutCert()
        val cryptoService = DefaultCryptoService(keyMaterial)
        val holderAgent = HolderAgent(keyMaterial)
        holderAgent.storeCredential(
            IssuerAgent().issueCredential(
                CredentialToBeIssued.VcSd(
                    claims = listOf(ClaimToBeIssued(EuPidScheme.Attributes.FAMILY_NAME, expectedFamilyName)),
                    expiration = Clock.System.now().plus(1.minutes),
                    scheme = EuPidScheme,
                    subjectPublicKey = keyMaterial.publicKey
                )
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

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

        // If the countdownLatch has been unlocked, the correct credential has been posted to the RP, and we're done!
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
        validate: (OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt) -> Unit,
    ): HttpClientEngine {
        val verifier = OidcSiopVerifier(
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.PreRegistered(clientId),
        )
        val responseEndpointPath = "/response"
        val jar = verifier.createAuthnRequestAsSignedRequestObject(
            requestOptions = OidcSiopVerifier.RequestOptions(
                credentials = setOf(
                    OidcSiopVerifier.RequestOptionsCredential(
                        credentialScheme = EuPidScheme,
                        representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                        requestedAttributes = listOf(
                            EuPidScheme.Attributes.FAMILY_NAME
                        )
                    )
                ),
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
                    if (result is OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt) {
                        validate(result)
                    }
                    respondOk()
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        }
    }
}