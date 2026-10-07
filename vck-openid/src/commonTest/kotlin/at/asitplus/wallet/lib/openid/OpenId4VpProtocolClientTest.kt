package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters.RequestUriMethod
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.formParameters
import at.asitplus.wallet.lib.oauth2.jsonResponse
import at.asitplus.wallet.lib.oauth2.kinds
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.oauth2.toErrorResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val OpenId4VpProtocolClientTest by matrixSuite {

    fun client(holder: OpenId4VpHolder = OpenId4VpHolder()) = OpenId4VpProtocolClient(openId4VpHolder = holder)

    val response = AuthenticationResponseResult.Post(
        url = "https://verifier.example.com/response",
        params = mapOf("response" to "eyJhbGciOiJFQ0RILUVTIn0.e30..", "state" to "a b&c=d"),
    )

    fun plainAnswer(body: String, headers: Headers = Headers.Empty) =
        ReceivedHttpResponse(HttpStatusCode.OK, headers, body)

    fun redirectUriAnswer(redirectUri: String) = jsonResponse(OpenId4VpSuccess(redirectUri))

    // Step sequences, see the KDoc of the methods of OpenId4VpProtocolClient

    val walletUrl = "https://wallet.example.com/"
    val requestUrl = "https://verifier.example.com/request"
    val verifierKeyMaterial = EphemeralKeyWithoutCert()
    val verifier = OpenId4VpVerifier(
        keyMaterial = verifierKeyMaterial,
        clientIdScheme = ClientIdScheme.PreRegistered("PRE-REGISTERED-CLIENT", "https://verifier.example.com/cb"),
    )
    val requestOptions = OpenId4VpRequestOptions(
        presentationRequest = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
        ).toDCQLRequest(),
    )

    suspend fun byReference(method: RequestUriMethod = RequestUriMethod.GET) = verifier.createAuthnRequest(
        requestOptions,
        CreationOptions.SignedRequestByReference(walletUrl, requestUrl, method),
    ).getOrThrow()

    /** The verifier's `request_uri` endpoint serving the request object of this request, see [requestUriEndpoint]. */
    fun CreatedRequest.endpoint(
        alter: (RequestObjectParameters?) -> RequestObjectParameters? = { it },
    ) = requestUriEndpoint(requestUrl) { loadRequestObject.shouldNotBeNull().invoke(alter(it)).getOrThrow() }

    /** The parameters of the request object of this request, as served for a GET. */
    suspend fun CreatedRequest.requestObjectParameters(): AuthenticationRequestParameters =
        JwsCompactTyped<AuthenticationRequestParameters>(
            loadRequestObject.shouldNotBeNull().invoke(null).getOrThrow()
        ).payload

    suspend fun AuthenticationRequestParameters.signed(): String =
        SignJwt<AuthenticationRequestParameters>(verifierKeyMaterial, JwsHeaderNone())(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            this,
            AuthenticationRequestParameters.serializer(),
        ).getOrThrow().toString()

    test("request passed by value sends no request") {
        val http = FakeHttpStack(scripted())
        val inQuery = verifier.createAuthnRequest(requestOptions, CreationOptions.Query(walletUrl)).getOrThrow()
        val signed = verifier.createAuthnRequest(requestOptions, CreationOptions.SignedRequestByValue(walletUrl))
            .getOrThrow()

        http.execute(client().prepareAuthorizationResponse(inQuery.url))
            .request.shouldBeInstanceOf<RequestParametersFrom.Uri<*>>()
        http.execute(client().prepareAuthorizationResponse(signed.url))
            .request.shouldBeInstanceOf<RequestParametersFrom.Jws<*>>()
        http.sent.shouldBeEmpty()
    }

    test("request that is not an authorization request is rejected") {
        // a request for remote signature creation (RQES), which is parsed into `SignatureRequestParameters`
        val input = """
            {
              "response_type": "sign_response",
              "client_id": "ff008dbe-0a00-43aa-8cbd-57b44fbd8cf9",
              "response_mode": "direct_post",
              "response_uri": "https://example.com/wallet/sd/upload",
              "nonce": "SD6caM6K17zn6lnvVlu9FQ92Je2rWg-rqbMegL1CBIY",
              "signatureQualifier": "eu_eidas_qes",
              "documentDigests": [
                { "hash": "dbe822af4b1cfddea8e8526a04a46557074d093cb02fee0f3dcc5f323629504e", "label": "sample.pdf" }
              ],
              "documentLocations": [
                { "uri": "https://example.com/rp/document/sample.pdf", "method": { "type": "public" } }
              ],
              "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
            }
        """.replace("\n", "").trimIndent()
        val http = FakeHttpStack(scripted())

        shouldThrow<OAuth2Exception.InvalidRequest> {
            http.execute(client().prepareAuthorizationResponse(input))
        }.message.shouldNotBeNull() shouldContain "SignatureRequestParameters"
        http.sent.shouldBeEmpty()
    }

    test("request object passed by reference is fetched with GET") {
        val request = byReference()
        val http = request.endpoint()

        http.execute(client().prepareAuthorizationResponse(request.url))
            .request.shouldBeInstanceOf<RequestParametersFrom.Jws<*>>()

        http.sent.kinds() shouldBe listOf("RequestObject")
        http.sent.single().http.apply {
            url shouldBe requestUrl
            method shouldBe HttpMethod.Get
            headers.getAll(HttpHeaders.Accept) shouldBe listOf(MediaTypes.Application.AUTHZ_REQ_JWT)
            body.shouldBeNull()
        }
    }

    test("request object passed by reference with request_uri_method=post is fetched with wallet metadata and nonce") {
        val request = byReference(RequestUriMethod.POST)
        val http = request.endpoint()

        val state = http.execute(client().prepareAuthorizationResponse(request.url))

        http.sent.kinds() shouldBe listOf("RequestObject")
        http.sent.single().http.apply {
            url shouldBe requestUrl
            method shouldBe HttpMethod.Post
            headers.getAll(HttpHeaders.Accept) shouldBe listOf(MediaTypes.Application.AUTHZ_REQ_JWT)
            headers.getAll(HttpHeaders.ContentType) shouldBe listOf("application/x-www-form-urlencoded")
            val sent = body.shouldNotBeNull().decodeFromFormUrlEncoded<RequestObjectParameters>()
            sent.walletMetadata.shouldNotBeNull()
            state.request.parameters.walletNonce shouldBe sent.walletNonce.shouldNotBeNull()
        }
    }

    test("request object without the wallet nonce sent fails") {
        val request = byReference(RequestUriMethod.POST)
        val http = request.endpoint { it?.copy(walletNonce = null) }

        shouldThrow<OAuth2Exception.InvalidRequest> {
            http.execute(client().prepareAuthorizationResponse(request.url))
        }.message.shouldNotBeNull() shouldContain "wallet_nonce"
        http.sent.kinds() shouldBe listOf("RequestObject")
    }

    test("request object encrypted to the key advertised in wallet metadata is decrypted") {
        val request = byReference(RequestUriMethod.POST)
        val http = request.endpoint()
        val holder = OpenId4VpHolder(ephemeralEncryptionKeyService = EphemeralEncryptionKeyService())

        http.execute(client(holder).prepareAuthorizationResponse(request.url))
            .request.decryptedFrom.shouldNotBeNull()
        http.sent.single().http.body.shouldNotBeNull()
            .decodeFromFormUrlEncoded<RequestObjectParameters>()
            .walletMetadata?.jsonWebKeySet?.keys.shouldNotBeNull().shouldBeSingleton()
    }

    test("jwks_uri in the verifier's client metadata is ignored") {
        val request = byReference()
        val requestObject = request.requestObjectParameters()
            .copy(clientMetadata = RelyingPartyMetadata(jsonWebKeySetUrl = "https://verifier.example.com/jwks"))
            .signed()
        val http = FakeHttpStack(scripted(plainAnswer(requestObject)))

        http.execute(client().prepareAuthorizationResponse(request.url)).jsonWebKeys.shouldBeNull()

        http.sent.kinds() shouldBe listOf("RequestObject")
    }

    test("non-success answer for the request object fails, also for a redirect") {
        val request = byReference()
        val http = FakeHttpStack(
            scripted(
                ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, ""),
                ReceivedHttpResponse(HttpStatusCode.Found, headersOf(HttpHeaders.Location, requestUrl), ""),
            )
        )

        shouldThrow<HttpErrorResponseException> {
            http.execute(client().prepareAuthorizationResponse(request.url))
        }.status shouldBe HttpStatusCode.NotFound
        shouldThrow<HttpErrorResponseException> {
            http.execute(client().prepareAuthorizationResponse(request.url))
        }.status shouldBe HttpStatusCode.Found
        http.sent.kinds() shouldBe listOf("RequestObject", "RequestObject")
    }

    test("authorization response is posted as form without charset") {
        val http = FakeHttpStack(scripted(plainAnswer("")))

        http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()

        http.sent.kinds() shouldBe listOf("AuthorizationResponse")
        http.sent.single().http.apply {
            url shouldBe response.url
            method shouldBe HttpMethod.Post
            headers.getAll(HttpHeaders.ContentType) shouldBe listOf("application/x-www-form-urlencoded")
            formParameters() shouldBe response.params
        }
    }

    test("redirect_uri of the verifier's answer is returned for an absolute https URI on any host") {
        val redirectUris = listOf(
            "https://verifier.example.com/cb#response_code=091535f699ea575c7937fa5f0f454aee",
            "https://other.example.org:8443/session?id=a%20b",
            "HTTPS://verifier.example.com",
        )
        val http = FakeHttpStack(scripted(*redirectUris.map { redirectUriAnswer(it) }.toTypedArray()))

        redirectUris.forEach {
            http.execute(client().sendAuthorizationResponse(response)) shouldBe it
        }
    }

    test("no redirect_uri for an empty or non-JSON body, or JSON without redirect_uri") {
        val bodies = listOf("", "OK", "<html></html>", "{}", """{"redirect_uri":""}""", """{"status":"ok"}""")
        val http = FakeHttpStack(scripted(*bodies.map { plainAnswer(it) }.toTypedArray()))

        repeat(bodies.size) {
            http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()
        }
    }

    test("redirect_uri that is not an absolute https URI fails") {
        val redirectUris = listOf(
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "intent://cb#Intent;scheme=eudi;package=com.example.attacker;end",
            "eudi-wallet://cb?code=1",
            "http://verifier.example.com/cb",
            "/cb#response_code=1",
            "//verifier.example.com/cb",
            "https:///cb",
            "https:verifier.example.com/cb",
            " https://verifier.example.com/cb",
        )
        val http = FakeHttpStack(scripted(*redirectUris.map { redirectUriAnswer(it) }.toTypedArray()))

        redirectUris.forEach {
            shouldThrow<IllegalArgumentException> {
                http.execute(client().sendAuthorizationResponse(response))
            }.message shouldBe "redirect_uri of the verifier is not an absolute https URI: $it"
        }
        http.sent.kinds() shouldBe redirectUris.map { "AuthorizationResponse" }
    }

    test("Location header of the verifier's answer is ignored") {
        val location = headersOf(HttpHeaders.Location, "https://attacker.example.com/")
        val http = FakeHttpStack(
            scripted(
                plainAnswer("", location),
                jsonResponse(OpenId4VpSuccess("https://verifier.example.com/cb")) {
                    append(HttpHeaders.Location, "https://attacker.example.com/")
                },
            )
        )

        http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()
        http.execute(client().sendAuthorizationResponse(response)) shouldBe "https://verifier.example.com/cb"
    }

    test("non-success answer fails, also for a redirect") {
        val redirect = ReceivedHttpResponse(
            status = HttpStatusCode.Found,
            headers = headersOf(HttpHeaders.Location, "https://verifier.example.com/cb"),
            body = "",
        )
        val http = FakeHttpStack(scripted(OAuth2Exception.InvalidRequest("unknown state").toErrorResponse(), redirect))

        shouldThrow<HttpErrorResponseException> {
            http.execute(client().sendAuthorizationResponse(response))
        }.apply {
            status shouldBe HttpStatusCode.BadRequest
            oauth2Error?.error shouldBe INVALID_REQUEST
        }
        shouldThrow<HttpErrorResponseException> {
            http.execute(client().sendAuthorizationResponse(response))
        }.status shouldBe HttpStatusCode.Found
        http.sent.kinds() shouldBe listOf("AuthorizationResponse", "AuthorizationResponse")
    }
}
