package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject

/**
 * Pins the lifecycle of authorization responses shared by [OpenId4VpVerifier] and [DcApiVerifier]: a response that
 * is correlated with its request ends that request, i.e. request, nonce and ephemeral encryption key are consumed
 * before anything else can fail, while a response that can not be correlated changes nothing.
 */
val OpenId4VpVerifierLifecycleTest by matrixSuite {

    val presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(AtomicAttribute2023, SD_JWT),
    ).toDCQLRequest()
    val callingOrigin = "https://example.com"
    val plaintextVpToken = AuthenticationResponseParameters(vpToken = JsonObject(emptyMap()))

    /** Stores of a verifier, to observe what processing a response consumes. */
    class Stores {
        val requests = DefaultMapStore<String, AuthenticationRequestParameters>()
        val nonces = DefaultNonceService()
        val keys = DefaultMapStore<String, String>()
        val keyService = EphemeralEncryptionKeyService(keys)

        suspend fun shouldBeConsumed(id: String, request: AuthenticationRequestParameters) {
            requests.get(id).shouldBeNull()
            nonces.verifyNonce(request.nonce.shouldNotBeNull()) shouldBe false
            request.encryptionKeyId?.let { keys.get(it).shouldBeNull() }
        }

        suspend fun shouldBeUntouched(id: String, request: AuthenticationRequestParameters) {
            requests.get(id) shouldBe request
            nonces.verifyNonce(request.nonce.shouldNotBeNull()) shouldBe true
            request.encryptionKeyId?.let { keys.get(it).shouldNotBeNull() }
        }

        private val AuthenticationRequestParameters.encryptionKeyId
            get() = clientMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()?.keyId
    }

    class UrlVerifier {
        val stores = Stores()
        val clientId = "https://example.com/rp/${uuid4()}"
        val verifier = OpenId4VpVerifier(
            clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            ephemeralEncryptionKeyService = stores.keyService,
            nonceService = stores.nonces,
            stateToAuthnRequestStore = stores.requests,
        )

        /** Creates a request, returning it as stored, i.e. with the nonce and key a response has to answer. */
        suspend fun createRequest(
            state: String,
            responseMode: OpenIdConstants.ResponseMode,
        ): AuthenticationRequestParameters {
            verifier.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    responseMode = responseMode,
                    responseUrl = clientId,
                    state = state,
                ),
                CreationOptions.Query("https://wallet.example.com/"),
            ).getOrThrow()
            return stores.requests.get(state).shouldNotBeNull()
        }
    }

    class DcVerifier(keyMaterial: KeyMaterial, certificate: X509Certificate) {
        val stores = Stores()
        val verifier = DcApiVerifier(
            keyMaterial = keyMaterial,
            // a scheme that conveys the encryption key in the request, as required for `dc_api.jwt`
            clientIdScheme = ClientIdScheme.CertificateHash(
                chain = listOf(certificate),
                redirectUri = "https://example.com/callback",
            ),
            ephemeralEncryptionKeyService = stores.keyService,
            nonceService = stores.nonces,
            stateToAuthnRequestStore = stores.requests,
        )

        /** Creates a request, returning it as stored, i.e. with the nonce and key a response has to answer. */
        suspend fun createRequest(
            externalId: String,
            responseMode: OpenIdConstants.ResponseMode,
            creationOptions: DcApiCreationOptions = DcApiCreationOptions.OpenId4VpUnsigned,
        ): AuthenticationRequestParameters {
            verifier.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    responseMode = responseMode,
                    expectedOrigins = listOf(callingOrigin),
                    state = externalId,
                ),
                creationOptions,
            ).getOrThrow()
            return stores.requests.get(externalId).shouldNotBeNull()
        }
    }

    suspend fun dcVerifier() = EphemeralKeyWithSelfSignedCert().let { DcVerifier(it, it.getCertificate()!!) }

    test("a plaintext response for direct_post.jwt fails, consuming request, nonce and key") {
        val f = UrlVerifier()
        val state = uuid4().toString()
        val request = f.createRequest(state, OpenIdConstants.ResponseMode.DirectPostJwt)

        f.verifier.validateAuthnResponse(ResponseParametersFrom.Post(plaintextVpToken.copy(state = state)))
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "requires encryption"

        f.stores.shouldBeConsumed(state, request)
    }

    test("a plaintext response for dc_api.jwt fails, consuming request, nonce and key") {
        val f = dcVerifier()
        val externalId = uuid4().toString()
        val request = f.createRequest(externalId, OpenIdConstants.ResponseMode.DcApiJwt)

        f.verifier.validateAuthnResponse(OpenId4VpResponseUnsigned(plaintextVpToken), externalId, callingOrigin)
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "requires encryption"

        f.stores.shouldBeConsumed(externalId, request)
    }

    test("a Digital Credentials API response to the URL verifier fails, consuming the request") {
        val f = UrlVerifier()
        val state = uuid4().toString()
        val request = f.createRequest(state, OpenIdConstants.ResponseMode.DirectPost)
        val response = ResponseParametersFrom.DcApi.createFromOpenId4VpResponse(
            OpenId4VpResponseUnsigned(plaintextVpToken.copy(state = state))
        )

        f.verifier.validateAuthnResponse(response)
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "use DcApiVerifier"

        f.stores.shouldBeConsumed(state, request)
    }

    test("a response to a signed DC API request from an unexpected origin fails, consuming the request") {
        val f = dcVerifier()
        val externalId = uuid4().toString()
        val request = f.createRequest(
            externalId,
            OpenIdConstants.ResponseMode.DcApi,
            DcApiCreationOptions.OpenId4VpSigned,
        )

        f.verifier.validateAuthnResponse(
            OpenId4VpResponseSigned(plaintextVpToken),
            externalId,
            "https://evil.example.com",
        ).exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "expected_origins"

        f.stores.shouldBeConsumed(externalId, request)
    }

    test("a response with an unknown state changes nothing") {
        val f = UrlVerifier()
        val state = uuid4().toString()
        val request = f.createRequest(state, OpenIdConstants.ResponseMode.DirectPostJwt)

        f.verifier.validateAuthnResponse(ResponseParametersFrom.Post(plaintextVpToken.copy(state = uuid4().toString())))
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "No authn request found"

        f.stores.shouldBeUntouched(state, request)
    }

    test("a response with an unknown externalId changes nothing") {
        val f = dcVerifier()
        val externalId = uuid4().toString()
        val request = f.createRequest(externalId, OpenIdConstants.ResponseMode.DcApiJwt)

        f.verifier.validateAuthnResponse(OpenId4VpResponseUnsigned(plaintextVpToken), uuid4().toString(), callingOrigin)
            .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "No authn request found"

        f.stores.shouldBeUntouched(externalId, request)
    }

    test("of concurrent responses to one request, at most one is processed") {
        val f = UrlVerifier()
        val state = uuid4().toString()
        val request = f.createRequest(state, OpenIdConstants.ResponseMode.DirectPost)
        val response = ResponseParametersFrom.Post(AuthenticationResponseParameters(state = state))

        val results = withContext(Dispatchers.Default) {
            List(16) { async { f.verifier.validateAuthnResponse(response) } }.awaitAll()
        }

        // the one processed response carries no vp_token, so it is processed, but not valid
        results.count { it.isSuccess } shouldBe 1
        results.filter { it.isFailure }.forEach {
            it.exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "No authn request found"
        }
        f.stores.shouldBeConsumed(state, request)
    }
}
