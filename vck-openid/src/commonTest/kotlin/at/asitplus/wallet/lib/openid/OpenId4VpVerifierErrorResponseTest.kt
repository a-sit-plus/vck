package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.formUrlEncode
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

/**
 * Authorization error responses of the wallet to [OpenId4VpVerifier] (OpenID4VP 1.0, 8.2, 8.3.1, 8.5): a correlated,
 * well-formed error is processed as [AuthnResponseResult.Error], ending the request like a presentation does.
 */
val OpenId4VpVerifierErrorResponseTest by matrixSuite {

    val presentationRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(AtomicAttribute2023, SD_JWT),
    ).toDCQLRequest()

    fixture {
        runBlocking {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also { issueAndStoreSdJwt(it, holderKeyMaterial) }
            object {
                val clientId = "https://example.com/rp/${uuid4()}"
                val requests = DefaultMapStore<String, AuthenticationRequestParameters>()
                val nonces = DefaultNonceService()
                val keys = DefaultMapStore<String, String>()
                val holder = OpenId4VpHolder(holder = holderAgent, randomSource = RandomSource.Default)
                val verifier = OpenId4VpVerifier(
                    clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(keys),
                    nonceService = nonces,
                    stateToAuthnRequestStore = requests,
                )

                /** Creates a request, returning its URL and the request as stored, i.e. with its nonce and key. */
                suspend fun createRequest(
                    state: String,
                    responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.DirectPost,
                ): Pair<String, AuthenticationRequestParameters> = verifier.createAuthnRequest(
                    OpenId4VpRequestOptions(
                        presentationRequest = presentationRequest,
                        responseMode = responseMode,
                        responseUrl = clientId,
                        state = state,
                    ),
                    CreationOptions.Query("https://wallet.example.com/"),
                ).getOrThrow().url to requests.get(state).shouldNotBeNull()

                /** The form the holder posts to answer [url] with [error]. */
                suspend fun errorResponseFor(url: String, error: Throwable): Map<String, String> =
                    holder.createAuthnErrorResponse(error, holder.prepareAuthorizationResponse(url).getOrThrow())
                        .getOrThrow().shouldBeInstanceOf<AuthenticationResponseResult.Post>().params

                /** The form the holder posts to answer [url] with a presentation. */
                suspend fun presentationFor(url: String): Map<String, String> =
                    holder.createAuthorizationResponse(url).getOrThrow()
                        .shouldBeInstanceOf<AuthenticationResponseResult.Post>().params

                suspend fun shouldBeConsumed(state: String, request: AuthenticationRequestParameters) {
                    requests.get(state).shouldBeNull()
                    nonces.verifyNonce(request.nonce.shouldNotBeNull()) shouldBe false
                    request.clientMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()?.keyId
                        ?.let { keys.get(it).shouldBeNull() }
                }
            }
        }
    } - {

        test("the authorization error response of OpenID4VP 1.0, 8.2 is processed, consuming request and nonce") {
            val state = uuid4().toString()
            val (_, request) = it.createRequest(state)

            it.verifier.validateAuthnResponse(
                "error=invalid_request&error_description=unsupported%20client_id_prefix&state=$state"
            ).getOrThrow() shouldBe AuthnResponseResult.Error(
                error = OAuth2Error(
                    error = "invalid_request",
                    errorDescription = "unsupported client_id_prefix",
                    state = state,
                ),
                request = request,
            )

            it.shouldBeConsumed(state, request)
        }

        test("the state of an error response finds the transaction") {
            val state = uuid4().toString()
            it.createRequest(state)

            it.verifier.validateAuthnResponse("error=access_denied&state=$state").getOrThrow()
                .state shouldBe state
        }

        test("an error code not defined by OpenID4VP 1.0 or RFC 6749 is processed, as the set is open (8.5)") {
            val state = uuid4().toString()
            it.createRequest(state)

            it.verifier.validateAuthnResponse("error=wallet_unavailable&state=$state").getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult.Error>().error.error shouldBe "wallet_unavailable"
        }

        test("a plaintext error for direct_post.jwt is processed (8.3.1), removing the ephemeral key") {
            val state = uuid4().toString()
            val (_, request) = it.createRequest(state, OpenIdConstants.ResponseMode.DirectPostJwt)
            request.clientMetadata?.jsonWebKeySet.shouldNotBeNull()

            it.verifier.validateAuthnResponse("error=access_denied&state=$state").getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult.Error>().error.error shouldBe "access_denied"

            it.shouldBeConsumed(state, request)
        }

        test("an encrypted error for direct_post.jwt is decrypted once") {
            val state = uuid4().toString()
            val (url, request) = it.createRequest(state, OpenIdConstants.ResponseMode.DirectPostJwt)
            val response = it.errorResponseFor(url, OAuth2Exception.AccessDenied("user declined"))
                .also { params -> params shouldHaveSize 1 } // only the "response" object
                .formUrlEncode()

            it.verifier.validateAuthnResponse(response).getOrThrow() shouldBe AuthnResponseResult.Error(
                error = OAuth2Error(error = "access_denied", errorDescription = "user declined", state = state),
                request = request,
            )
            it.shouldBeConsumed(state, request)

            it.verifier.validateAuthnResponse(response).isFailure shouldBe true
        }

        test("an error the holder can't encrypt for direct_post.jwt is sent without encryption (8.3.1)") {
            // a pre-registered client conveys no key in the request, and the holder knows none out-of-band
            val verifier = OpenId4VpVerifier(
                clientIdScheme = ClientIdScheme.PreRegistered("client-${uuid4()}", "https://example.com/cb"),
            )
            val state = uuid4().toString()
            val url = verifier.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                    responseUrl = "https://example.com/response",
                    state = state,
                ),
                CreationOptions.SignedRequestByValue("https://wallet.example.com/"),
            ).getOrThrow().url
            val preparation = it.holder.prepareAuthorizationResponse(url).getOrThrow()

            // a presentation is never sent without encryption
            it.holder.finalizeAuthorizationResponse(preparation).isFailure shouldBe true

            val declined = OAuth2Exception.AccessDenied("user declined")
            val response = it.holder.createAuthnErrorResponse(declined, preparation).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Post>()
            response.params.keys shouldBe setOf("error", "error_description", "state")
            verifier.validateAuthnResponse(response.params.formUrlEncode()).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult.Error>().error shouldBe
                    OAuth2Error(error = "access_denied", errorDescription = "user declined", state = state)
        }

        test("parameters next to an encrypted error are not processed, but end the request") {
            val state = uuid4().toString()
            val (url, request) = it.createRequest(state, OpenIdConstants.ResponseMode.DirectPostJwt)
            val response = it.errorResponseFor(url, OAuth2Exception.AccessDenied())

            val tampered = response + ("error" to "invalid_request")

            it.verifier.validateAuthnResponse(tampered.formUrlEncode()).exceptionOrNull()
                .shouldNotBeNull().message.shouldNotBeNull() shouldContain "next to an encoded response"

            it.shouldBeConsumed(state, request)
        }

        test("an error ends the request, so a presentation for it is not processed afterwards") {
            val state = uuid4().toString()
            val (url, _) = it.createRequest(state)
            val presentation = it.presentationFor(url)

            it.verifier.validateAuthnResponse("error=access_denied&state=$state").getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult.Error>()

            it.verifier.validateAuthnResponse(presentation.formUrlEncode())
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "No authn request found"
        }

        test("a presentation ends the request, so an error for it is not processed afterwards") {
            val state = uuid4().toString()
            val (url, _) = it.createRequest(state)

            it.verifier.validateAuthnResponse(it.presentationFor(url).formUrlEncode()).getOrThrow()
                .vpTokenOrThrow()

            it.verifier.validateAuthnResponse("error=access_denied&state=$state")
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "No authn request found"
        }

        "a malformed error response is not processed, but ends the request" - { f ->
            // the form body, and why it is rejected
            mapOf(
                "error with vp_token" to ("error=access_denied&vp_token=%7B%7D" to "with vp_token or code"),
                "error with code" to ("error=access_denied&code=abc" to "with vp_token or code"),
                "blank error" to ("error=%20" to "error is blank"),
                "error_description without error" to ("error_description=declined" to "require error"),
                "error_uri without error" to ("error_uri=https%3A%2F%2Fexample.com%2Ferror" to "require error"),
                "error with a quotation mark" to ("error=access%22denied" to "error is blank or contains"),
                "error_description with a non-ASCII character" to
                        ("error=access_denied&error_description=caf%C3%A9" to "error_description contains"),
                "error_uri with a space" to
                        ("error=access_denied&error_uri=https%3A%2F%2Fexample.com%2Fa%20b" to "error_uri contains"),
            ).asData() test { (_, case) ->
                val (body, reason) = case
                val state = uuid4().toString()
                val (_, request) = f.createRequest(state)

                f.verifier.validateAuthnResponse("$body&state=$state")
                    .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain reason

                f.shouldBeConsumed(state, request)
            }
        }
    }
}
