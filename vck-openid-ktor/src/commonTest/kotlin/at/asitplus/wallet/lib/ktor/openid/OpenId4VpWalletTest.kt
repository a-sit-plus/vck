package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult.SuccessIso
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult.SuccessSdJwt
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.engine.mock.*
import io.ktor.client.request.*
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
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random
import kotlin.time.Duration.Companion.minutes

class OpenId4VpWalletTest : FunSpec() {

    lateinit var countdownLatch: Mutex
    lateinit var keyMaterial: KeyMaterial
    lateinit var cryptoService: CryptoService
    lateinit var holderAgent: HolderAgent

    init {
        beforeEach {
            countdownLatch = Mutex(true)
            keyMaterial = EphemeralKeyWithoutCert()
            cryptoService = DefaultCryptoService(keyMaterial)
            holderAgent = HolderAgent(keyMaterial)
        }

        test("presentEuPidCredentialSdJwtDirectPost") {
            runTest {
                val (wallet, url) = setup(
                    scheme = EuPidScheme,
                    representation = SD_JWT,
                    attributes = mapOf(
                        EuPidScheme.Attributes.FAMILY_NAME to randomString()
                    ),
                    responseMode = ResponseMode.DirectPost,
                    clientId = uuid4().toString()
                )

                val requestParametersFrom = wallet.parseAuthenticationRequestParameters(url).getOrThrow()
                // sends the response to the mock RP, which calls verifyReceivedAttributes, which unlocks the latch
                wallet.startPresentation(requestParametersFrom).apply {
                    this.isSuccess shouldBe true
                }

                assertPresentation(countdownLatch)
            }
        }


        test(" presentEuPidCredentialIsoQuery") {
            runTest {
                val (wallet, url) = setup(
                    scheme = EuPidScheme,
                    representation = ISO_MDOC,
                    attributes = mapOf(
                        EuPidScheme.Attributes.GIVEN_NAME to randomString()
                    ),
                    responseMode = ResponseMode.Query,
                    clientId = uuid4().toString()
                )

                val requestParametersFrom = wallet.parseAuthenticationRequestParameters(url).getOrThrow()
                // sends the response to the mock RP, which calls verifyReceivedAttributes, which unlocks the latch
                wallet.startPresentation(requestParametersFrom).apply {
                    this.isSuccess shouldBe true
                }

                assertPresentation(countdownLatch)
            }
        }
    }

    private fun randomString(): String = Random.nextBytes(32).encodeToString(Base16)

    suspend fun setup(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
        responseMode: ResponseMode,
        clientId: String,
    ): Pair<OpenId4VpWallet, String> {
        val requestOptions = OidcSiopVerifier.RequestOptions(
            credentials = setOf(
                OidcSiopVerifier.RequestOptionsCredential(
                    credentialScheme = scheme,
                    representation = representation,
                    requestedAttributes = attributes.keys.toList()
                )
            ),
            responseMode = responseMode,
        )
        holderAgent.storeMockCredentials(scheme, representation, attributes)
        val (mockEngine, url) = setupRelyingPartyService(clientId, requestOptions) {
            it.verifyReceivedAttributes(attributes)
        }
        val wallet = setupWallet(mockEngine)
        return wallet to url
    }

    private fun setupWallet(mockEngine: HttpClientEngine): OpenId4VpWallet = OpenId4VpWallet(
        openUrlExternally = { HttpClient(mockEngine).get(it) },
        engine = mockEngine,
        cryptoService = cryptoService,
        holderAgent = holderAgent,
    )

    private suspend fun HolderAgent.storeMockCredentials(
        scheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        attributes: Map<String, String>,
    ) {
        storeCredential(
            IssuerAgent(EphemeralKeyWithSelfSignedCert()).issueCredential(
                representation.toCredentialToBeIssued(scheme, attributes)
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
    }

    private fun ConstantIndex.CredentialRepresentation.toCredentialToBeIssued(
        scheme: ConstantIndex.CredentialScheme,
        attributes: Map<String, String>,
    ): CredentialToBeIssued = when (this) {
        SD_JWT -> CredentialToBeIssued.VcSd(
            claims = attributes.map { it.toClaimToBeIssued() },
            expiration = Clock.System.now().plus(1.minutes),
            scheme = scheme,
            subjectPublicKey = keyMaterial.publicKey
        )

        ISO_MDOC -> CredentialToBeIssued.Iso(
            issuerSignedItems = attributes.map { it.toIssuerSignedItem() },
            expiration = Clock.System.now().plus(1.minutes),
            scheme = scheme,
            subjectPublicKey = keyMaterial.publicKey
        )

        else -> TODO()
    }

    private fun Map.Entry<String, String>.toClaimToBeIssued(): ClaimToBeIssued = ClaimToBeIssued(key, value)

    private fun Map.Entry<String, String>.toIssuerSignedItem(): IssuerSignedItem =
        IssuerSignedItem(0U, Random.nextBytes(16), key, value)

    private fun OidcSiopVerifier.AuthnResponseResult.verifyReceivedAttributes(expectedAttributes: Map<String, String>) {
        if (this.containsAllAttributes(expectedAttributes)) {
            countdownLatch.unlock()
        }
    }

    private fun OidcSiopVerifier.AuthnResponseResult.containsAllAttributes(expectedAttributes: Map<String, String>): Boolean =
        when (this) {
            is SuccessSdJwt -> this.containsAllAttributes(expectedAttributes)
            is SuccessIso -> this.containsAllAttributes(expectedAttributes)
            else -> false
        }

    private fun SuccessSdJwt.containsAllAttributes(attributes: Map<String, String>): Boolean =
        attributes.all { containsAttribute(it) }

    private fun SuccessSdJwt.containsAttribute(attribute: Map.Entry<String, String>): Boolean =
        disclosures.toList().any { it.matchesAttribute(attribute) }

    private fun SuccessIso.containsAllAttributes(attributes: Map<String, String>): Boolean =
        attributes.all { containsAttribute(it) }

    private fun SuccessIso.containsAttribute(attribute: Map.Entry<String, String>): Boolean =
        documents.any { doc -> doc.validItems.any { it.matchesAttribute(attribute) } }

    private fun SelectiveDisclosureItem.matchesAttribute(attribute: Map.Entry<String, String>): Boolean =
        claimName == attribute.key && claimValue.jsonPrimitive.content == attribute.value

    private fun IssuerSignedItem.matchesAttribute(attribute: Map.Entry<String, String>): Boolean =
        elementIdentifier == attribute.key && elementValue.toString() == attribute.value

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
        clientId: String,
        requestOptions: OidcSiopVerifier.RequestOptions,
        validate: (OidcSiopVerifier.AuthnResponseResult) -> Unit,
    ): Pair<HttpClientEngine, String> {
        val requestEndpointPath = "/request/${uuid4()}"
        val verifier = OidcSiopVerifier(
            clientIdScheme = OidcSiopVerifier.ClientIdScheme.PreRegistered(clientId),
        )
        val responseEndpointPath = "/response"
        val (url, jar) = verifier.createAuthnRequestUrlWithRequestObjectByReference(
            walletUrl = "http://wallet.example.com/",
            requestUrl = "http://rp.example.com$requestEndpointPath",
            requestOptions = requestOptions.copy(responseUrl = responseEndpointPath)
        ).getOrThrow()

        return MockEngine { request ->
            when {
                request.url.fullPath == requestEndpointPath -> respond(jar)

                request.url.fullPath.startsWith(responseEndpointPath) or request.url.fullPath.startsWith("/$clientId") -> {
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
        } to url
    }
}
