package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.openid.*
import at.asitplus.wallet.lib.openid.AuthnResponseResult.SuccessIso
import at.asitplus.wallet.lib.openid.AuthnResponseResult.SuccessSdJwt
import at.asitplus.wallet.lib.openid.OpenId4VpVerifier.CreationOptions
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
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
    lateinit var holderAgent: HolderAgent

    init {
        beforeEach {
            countdownLatch = Mutex(true)
            keyMaterial = EphemeralKeyWithoutCert()
            holderAgent = HolderAgent(keyMaterial)
        }

        test("presentEuPidCredentialSdJwtDirectPost") {
            runTest {
                val (wallet, url, mockEngine) = setup(
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
                wallet.startPresentationReturningUrl(requestParametersFrom).also {
                    it.isSuccess shouldBe true
                    it.getOrThrow().redirectUri?.let { HttpClient(mockEngine).get(it) }
                }

                assertPresentation(countdownLatch)
            }
        }


        test(" presentEuPidCredentialIsoQuery") {
            runTest {
                val (wallet, url, mockEngine) = setup(
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
                wallet.startPresentationReturningUrl(requestParametersFrom).also {
                    it.isSuccess shouldBe true
                    it.getOrThrow().redirectUri?.let { HttpClient(mockEngine).get(it) }
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
    ): Triple<OpenId4VpWallet, String, HttpClientEngine> {
        val requestOptions = OpenIdRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = scheme,
                    representation = representation,
                    requestedAttributes = attributes.keys
                )
            ),
            responseMode = responseMode,
        )
        holderAgent.storeMockCredentials(scheme, representation, attributes)
        val (mockEngine, url) = setupRelyingPartyService(clientId, requestOptions) {
            it.verifyReceivedAttributes(attributes)
        }
        val wallet = setupWallet(mockEngine)
        return Triple(wallet, url, mockEngine)
    }

    private fun setupWallet(mockEngine: HttpClientEngine): OpenId4VpWallet = OpenId4VpWallet(
        engine = mockEngine,
        keyMaterial = keyMaterial,
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

    private fun AuthnResponseResult.verifyReceivedAttributes(expectedAttributes: Map<String, String>) {
        if (this.containsAllAttributes(expectedAttributes)) {
            countdownLatch.unlock()
        }
    }

    private fun AuthnResponseResult.containsAllAttributes(expectedAttributes: Map<String, String>): Boolean =
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
        requestOptions: OpenIdRequestOptions,
        validate: (AuthnResponseResult) -> Unit,
    ): Pair<HttpClientEngine, String> {
        val requestEndpointPath = "/request/${uuid4()}"
        val redirectUri = "http://rp.example.com/cb"
        val verifier = OpenId4VpVerifier(
            clientIdScheme = ClientIdScheme.PreRegistered(clientId, redirectUri),
        )
        val responseEndpointPath = "/response"
        val (url, jar) = verifier.createAuthnRequest(
            requestOptions.copy(responseUrl = responseEndpointPath),
            CreationOptions.SignedRequestByReference("http://wallet.example.com/", "http://rp.example.com$requestEndpointPath")
        ).getOrThrow()
        jar.shouldNotBeNull()

        return MockEngine { request ->
            when {
                request.url.fullPath == requestEndpointPath -> respond(jar.invoke(null).getOrThrow())

                request.url.fullPath.startsWith(responseEndpointPath) or request.url.toString().startsWith(redirectUri) -> {
                    val requestBody = request.body.toByteArray().decodeToString()
                    val queryParameters: Map<String, String> =
                        request.url.parameters.toMap().entries.associate { it.key to it.value.first() }
                    val result = if (requestBody.isNotEmpty()) verifier.validateAuthnResponse(requestBody)
                    else verifier.validateAuthnResponse(queryParameters)
                    validate(result)
                    respondOk()
                }

                else -> respondError(HttpStatusCode.NotFound)
                    .also { Napier.w("NOT MATCHED ${request.url.fullPath}") }
            }
        } to url
    }
}
