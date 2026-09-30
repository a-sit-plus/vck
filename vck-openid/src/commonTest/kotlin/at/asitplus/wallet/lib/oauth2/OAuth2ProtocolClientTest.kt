package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

val OAuth2ProtocolClientTest by matrixSuite {

    val asUrl = "https://as.example.com"
    val clientId = "https://example.com/rp"

    fun scriptedMetadata(
        tokenEndPointAuthMethods: Set<String>? = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH),
        pushedAuthorizationRequestEndpoint: String? = null,
        requireSignedRequestObject: Boolean? = null,
    ) = OAuth2AuthorizationServerMetadata(
        issuer = asUrl,
        authorizationEndpoint = "$asUrl/authorize",
        pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint,
        tokenEndpoint = "$asUrl/token",
        introspectionEndpoint = "$asUrl/introspect",
        challengeEndpoint = "$asUrl/challenge",
        tokenEndPointAuthMethodsSupported = tokenEndPointAuthMethods,
        dpopSigningAlgValuesSupportedStrings = setOf(JwsAlgorithm.Signature.ES256.identifier),
        requestObjectSigningAlgorithmsSupportedStrings = setOf(JwsAlgorithm.Signature.ES256.identifier),
        requireSignedRequestObject = requireSignedRequestObject,
    )

    fun clientWithoutAttestation() = OAuth2ProtocolClient(
        oAuth2Client = OAuth2Client(clientId = clientId),
        randomSource = RandomSource.Default,
    )

    fun clientWithAttestation(
        captureAttestationInput: ((OAuth2ProtocolClient.LoadInstanceAttestationInput) -> Unit)? = null,
        attestedKey: KeyMaterial = EphemeralKeyWithoutCert(),
        keyMaterial: KeyMaterial = attestedKey,
    ) = OAuth2ProtocolClient(
        oAuth2Client = OAuth2Client(clientId = clientId),
        keyMaterial = keyMaterial,
        randomSource = RandomSource.Default,
        loadInstanceAttestation = {
            captureAttestationInput?.invoke(it)
            catching {
                BuildClientAttestationJwt(
                    SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                    clientId = clientId,
                    clientKey = attestedKey.jsonWebKey,
                )
            }
        },
    )

    fun OAuth2ProtocolClient.preAuthTokenRequest(metadata: OAuth2AuthorizationServerMetadata) =
        requestTokenWithPreAuthorizedCode(
            oauthMetadata = metadata,
            authorizationServer = metadata.issuer,
            preAuthorizedCode = uuid4().toString(),
            transactionCode = null,
            scope = "scope",
            authorizationDetails = setOf(),
        )

    fun tokenResponse(dpopNonce: String? = null) = jsonResponse(
        TokenResponseParameters(accessToken = uuid4().toString(), tokenType = TOKEN_TYPE_DPOP)
    ) { dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) } }

    fun challengeResponse(challenge: String) = jsonResponse(AttestationChallengeResponse(challenge))

    fun resourceServerNonceError(nonce: String) = ReceivedHttpResponse(
        status = HttpStatusCode.Unauthorized,
        headers = headers {
            append(HttpHeaders.WWWAuthenticate, "DPoP error=\"$USE_DPOP_NONCE\"")
            append(HttpHeaders.DPoPNonce, nonce)
        },
        body = "",
    )

    // Step sequences, see the KDoc of the methods of OAuth2ProtocolClient

    test("AS metadata comes from the OAuth 2.0 well-known path") {
        val http = FakeHttpStack(scripted(jsonResponse(scriptedMetadata())))

        http.execute(clientWithoutAttestation().loadAuthorizationServerMetadata(asUrl)).issuer shouldBe asUrl

        http.sent.kinds() shouldBe listOf("AuthorizationServerMetadata")
        http.sent.single().http.path shouldBe "/.well-known/oauth-authorization-server"
    }

    test("AS metadata falls back to the OpenID configuration") {
        val http = FakeHttpStack(
            scripted(
                ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, ""),
                jsonResponse(scriptedMetadata()),
            )
        )

        http.execute(clientWithoutAttestation().loadAuthorizationServerMetadata(asUrl)).issuer shouldBe asUrl

        http.sent.kinds() shouldBe listOf(
            "AuthorizationServerMetadata",
            "AuthorizationServerMetadata(openidConfiguration)"
        )
        http.sent.last().http.path shouldBe "/.well-known/openid-configuration"
    }

    test("AS metadata fails when both well-known paths fail") {
        val http = FakeHttpStack(
            scripted(
                jsonResponse("not metadata"),
                ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, ""),
            )
        )

        shouldThrow<HttpErrorResponseException> {
            http.execute(clientWithoutAttestation().loadAuthorizationServerMetadata(asUrl))
        }.status shouldBe HttpStatusCode.NotFound
    }

    test("authorization without PAR sends no request") {
        val http = FakeHttpStack(scripted())

        val result = http.execute(
            clientWithoutAttestation().startAuthorization(scriptedMetadata(), asUrl, scope = "scope")
        )

        http.sent.shouldBeEmpty()
        Url(result.url).parameters["prompt"] shouldBe "login"
    }

    test("token request without client attestation sends only the token request") {
        val http = FakeHttpStack(scripted(tokenResponse()))

        http.execute(clientWithoutAttestation().preAuthTokenRequest(scriptedMetadata()))

        http.sent.kinds() shouldBe listOf("Token(0)")
    }

    test("token request with client attestation fetches an attestation challenge first") {
        val http = FakeHttpStack(scripted(challengeResponse("c1"), tokenResponse()))

        http.execute(clientWithAttestation().preAuthTokenRequest(scriptedMetadata()))

        http.sent.kinds() shouldBe listOf("AttestationChallenge", "Token(0)")
        http.sent[1].toRequestInfo().clientAttestationPop.shouldNotBeNull().payload.challenge shouldBe "c1"
    }

    test("token request retries with the DPoP nonce, fetching a new attestation challenge") {
        val http = FakeHttpStack(
            scripted(
                challengeResponse("c1"),
                OAuth2Exception.UseDpopNonce("n1").toErrorResponse(),
                challengeResponse("c2"),
                tokenResponse(),
            )
        )

        http.execute(clientWithAttestation().preAuthTokenRequest(scriptedMetadata()))

        http.sent.kinds() shouldBe listOf("AttestationChallenge", "Token(0)", "AttestationChallenge", "Token(1)")
        http.sent[3].toRequestInfo().apply {
            dpop.shouldNotBeNull().payload.nonce shouldBe "n1"
            clientAttestationPop.shouldNotBeNull().payload.challenge shouldBe "c2"
        }
    }

    test("token request retries with the attestation challenge from the error") {
        val http = FakeHttpStack(
            scripted(
                challengeResponse("c1"),
                OAuth2Exception.UseAttestationChallenge("c2").toErrorResponse(),
                tokenResponse(),
            )
        )

        http.execute(clientWithAttestation().preAuthTokenRequest(scriptedMetadata()))

        http.sent.kinds() shouldBe listOf("AttestationChallenge", "Token(0)", "Token(1)")
        http.sent[2].toRequestInfo().clientAttestationPop.shouldNotBeNull().payload.challenge shouldBe "c2"
    }

    test("token request fails after two retries") {
        val http = FakeHttpStack(
            scripted(
                OAuth2Exception.UseDpopNonce("n1").toErrorResponse(),
                OAuth2Exception.UseDpopNonce("n2").toErrorResponse(),
                OAuth2Exception.UseDpopNonce("n3").toErrorResponse(),
            )
        )

        shouldThrow<HttpErrorResponseException> {
            http.execute(clientWithoutAttestation().preAuthTokenRequest(scriptedMetadata()))
        }.oauth2Error.shouldNotBeNull().error shouldBe USE_DPOP_NONCE

        http.sent.kinds() shouldBe listOf("Token(0)", "Token(1)", "Token(2)")
    }

    test("token request is not retried for other errors") {
        val http = FakeHttpStack(scripted(OAuth2Exception.InvalidRequest("nope").toErrorResponse()))

        shouldThrow<HttpErrorResponseException> {
            http.execute(clientWithoutAttestation().preAuthTokenRequest(scriptedMetadata()))
        }

        http.sent.kinds() shouldBe listOf("Token(0)")
    }

    test("combined mode fetches no attestation challenge while a DPoP nonce is cached") {
        val metadata = scriptedMetadata(tokenEndPointAuthMethods = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH_DPOP))
        val client = clientWithoutAttestation()
        val http = FakeHttpStack(scripted(challengeResponse("c1"), tokenResponse(dpopNonce = "n1"), tokenResponse()))

        http.execute(client.preAuthTokenRequest(metadata))
        http.execute(client.preAuthTokenRequest(metadata))

        http.sent.kinds() shouldBe listOf("AttestationChallenge", "Token(0)", "Token(0)")
        http.sent[1].toRequestInfo().dpop.shouldNotBeNull().payload.nonce shouldBe "c1"
        http.sent[2].toRequestInfo().dpop.shouldNotBeNull().payload.nonce shouldBe "n1"
    }

    test("userinfo request retries once with the DPoP nonce from WWW-Authenticate") {
        val token = TokenResponseParameters(accessToken = uuid4().toString(), tokenType = TOKEN_TYPE_DPOP)
        val http = FakeHttpStack(
            scripted(resourceServerNonceError("n1"), jsonResponse(buildJsonObject { put("sub", "foo") }))
        )

        http.execute(clientWithoutAttestation().userInfoRequest("$asUrl/userinfo", token))

        http.sent.kinds() shouldBe listOf("UserInfo(0)", "UserInfo(1)")
        http.sent[1].http.headers[HttpHeaders.Authorization] shouldBe token.toHttpHeaderValue()
        http.sent[1].toRequestInfo().dpop.shouldNotBeNull().payload.apply {
            nonce shouldBe "n1"
            accessTokenHash.shouldNotBeNull()
        }
    }

    test("userinfo request fails after one retry") {
        val token = TokenResponseParameters(accessToken = uuid4().toString(), tokenType = TOKEN_TYPE_DPOP)
        val http = FakeHttpStack(scripted(resourceServerNonceError("n1"), resourceServerNonceError("n2")))

        shouldThrow<HttpErrorResponseException> {
            http.execute(clientWithoutAttestation().userInfoRequest("$asUrl/userinfo", token))
        }.status shouldBe HttpStatusCode.Unauthorized

        http.sent.kinds() shouldBe listOf("UserInfo(0)", "UserInfo(1)")
    }

    // Request bodies are built once per exchange

    test("retried PAR reuses the signed request object") {
        val metadata = scriptedMetadata(
            tokenEndPointAuthMethods = null,
            pushedAuthorizationRequestEndpoint = "$asUrl/par",
            requireSignedRequestObject = true,
        )
        val http = FakeHttpStack(
            scripted(
                OAuth2Exception.UseDpopNonce("n1").toErrorResponse(),
                jsonResponse(PushedAuthenticationResponseParameters(requestUri = "urn:example:par")),
            )
        )

        val result = http.execute(clientWithoutAttestation().startAuthorization(metadata, asUrl, scope = "scope"))

        http.sent.kinds() shouldBe listOf("PushedAuthorization(0)", "PushedAuthorization(1)")
        http.sent[0].http.formParameters()["request"].shouldNotBeNull()
        http.sent[1].http.body shouldBe http.sent[0].http.body
        Url(result.url).parameters["request_uri"] shouldBe "urn:example:par"
    }

    test("retried token request reuses the PKCE code verifier") {
        val metadata = scriptedMetadata(tokenEndPointAuthMethods = null)
        val client = clientWithoutAttestation()
        val authorization = FakeHttpStack(scripted())
            .execute(client.startAuthorization(metadata, asUrl, scope = "scope"))
        val http = FakeHttpStack(scripted(OAuth2Exception.UseDpopNonce("n1").toErrorResponse(), tokenResponse()))

        http.execute(
            client.requestTokenWithAuthCode(
                oauthMetadata = metadata,
                url = "$clientId/callback?code=${uuid4()}&state=${authorization.state}",
                authorizationServer = asUrl,
                state = authorization.state,
                scope = "scope",
            )
        )

        http.sent.kinds() shouldBe listOf("Token(0)", "Token(1)")
        http.sent[0].http.formParameters()["code_verifier"].shouldNotBeNull()
        http.sent[1].http.body shouldBe http.sent[0].http.body
    }

    test("retried token introspection passes the issuer metadata to the attestation loader") {
        val inputs = mutableListOf<OAuth2ProtocolClient.LoadInstanceAttestationInput>()
        val issuerMetadata = AuthorizationServerFixture(requirePAR = false).credentialIssuer.metadata
        val http = FakeHttpStack(
            scripted(
                challengeResponse("c1"),
                OAuth2Exception.UseDpopNonce("n1").toErrorResponse(),
                challengeResponse("c2"),
                jsonResponse(TokenIntrospectionResponse(active = true)),
            )
        )

        http.execute(
            clientWithAttestation(captureAttestationInput = { inputs += it }).callTokenIntrospection(
                oauthMetadata = scriptedMetadata(),
                request = TokenIntrospectionRequest(token = uuid4().toString()),
                popAudience = asUrl,
                issuerMetadata = issuerMetadata,
            )
        ).active shouldBe true

        http.sent.kinds() shouldBe listOf(
            "AttestationChallenge", "TokenIntrospection(0)", "AttestationChallenge", "TokenIntrospection(1)"
        )
        inputs.map { it.credentialIssuer } shouldBe List(2) { issuerMetadata.credentialIssuer }
    }

    test("exchange rejects calls in the wrong state") {
        val metadata = scriptedMetadata()

        val passingResponseFirst = clientWithoutAttestation().preAuthTokenRequest(metadata)
        passingResponseFirst.next(tokenResponse()).exceptionOrNull().shouldNotBeNull()
        passingResponseFirst.next().exceptionOrNull().shouldNotBeNull()

        val missingResponse = clientWithoutAttestation().preAuthTokenRequest(metadata)
        missingResponse.next().getOrThrow().shouldBeInstanceOf<HttpStep.Send>()
        missingResponse.next().exceptionOrNull().shouldNotBeNull()
        missingResponse.next(tokenResponse()).exceptionOrNull().shouldNotBeNull()

        val finished = clientWithoutAttestation().preAuthTokenRequest(metadata)
        finished.next().getOrThrow().shouldBeInstanceOf<HttpStep.Send>()
        finished.next(tokenResponse()).getOrThrow().shouldBeInstanceOf<HttpStep.Done<*>>()
        finished.next().exceptionOrNull().shouldNotBeNull()
    }

    // Client authentication and DPoP against an actual authorization server

    test("token introspection handles jwt response") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val tokenResponse = authorizationCodeFlow()

            http.execute(
                client.callTokenIntrospection(
                    oauthMetadata = metadata(),
                    request = TokenIntrospectionRequest(
                        token = tokenResponse.params.accessToken,
                        tokenTypeHint = tokenResponse.params.tokenType,
                        responseFormat = TokenIntrospectionRequest.ResponseFormat.JWT,
                    ),
                    popAudience = authorizationService.publicContext,
                )
            ).active shouldBe true
        }
    }

    test("fails before sending when keyMaterial does not match the cnf key in the instance attestation") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val client = clientWithAttestation(
                attestedKey = EphemeralKeyWithoutCert(), // WIA attests a different key
                keyMaterial = EphemeralKeyWithoutCert(), // PoP signed with this key — does not match cnf
            )

            client.preAuthTokenRequest(metadata()).next().exceptionOrNull()
                .shouldNotBeNull().message.shouldNotBeNull() shouldContain "does not match"
        }
    }

    /**
     * draft-10 8 puts the client authentication method in `token_endpoint_auth_methods_supported`, while
     * `client_attestation_pop_methods_supported` (7.6) is about presenting an attestation as an *additional*
     * security signal and MAY be omitted, so the mode must be selected from the former.
     */
    test("sends a dedicated PoP when the AS advertises the auth method but no PoP methods") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val metadata = metadata().copy(
                tokenEndPointAuthMethodsSupported = setOf(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH),
                clientAttestationPopMethodsSupported = null,
            )

            val request = http.firstRequest<ProtocolRequest.Token>(client.preAuthTokenRequest(metadata))
                .toRequestInfo()

            request.clientAttestation.shouldNotBeNull()
            request.clientAttestationPop.shouldNotBeNull()
        }
    }

    test("combined mode metadata does not break a client that sends no attestation") {
        with(
            AuthorizationServerFixture(
                requirePAR = false,
                popMethods = setOf(ClientAttestationPopMethod.DpopCombined),
            )
        ) {
            // No loadInstanceAttestation, and the two keys are independent because none of them is attested
            val plainDpopClient = OAuth2ProtocolClient(
                oAuth2Client = OAuth2Client(clientId = "https://example.com/rp-no-attestation"),
                randomSource = RandomSource.Default,
            )

            val request = http.firstRequest<ProtocolRequest.Token>(plainDpopClient.preAuthTokenRequest(metadata()))
                .toRequestInfo()

            request.clientAttestation.shouldBeNull()
            request.dpop.shouldNotBeNull()
        }
    }

    test("instance attestation callbacks receive authorization server context") {
        var attestationInput: OAuth2ProtocolClient.LoadInstanceAttestationInput? = null

        with(AuthorizationServerFixture(requirePAR = true, captureAttestationInput = { attestationInput = it })) {
            http.execute(
                client.startAuthorization(
                    oauthMetadata = metadata(),
                    authorizationServer = authorizationService.publicContext,
                    scope = requestedScope,
                    issuerMetadata = credentialIssuer.metadata,
                )
            )

            attestationInput.shouldNotBeNull().also {
                it.authorizationServer shouldBe authorizationService.publicContext
                it.credentialIssuer shouldBe credentialIssuer.metadata.credentialIssuer
                it.preferredClientStatusPeriod shouldBe credentialIssuer.metadata.preferredClientStatusPeriod
            }
        }
    }

    test("fetches advertised attestation challenge for the PAR PoP") {
        with(AuthorizationServerFixture(requirePAR = true)) {
            http.execute(
                client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
            )

            // PAR mandates a fresh DPoP nonce, which the client can only learn from the rejected first attempt,
            // so two PARs are sent, each carrying a freshly fetched challenge in its PoP.
            http.sent.kinds() shouldBe listOf(
                "AttestationChallenge", "PushedAuthorization(0)", "AttestationChallenge", "PushedAuthorization(1)"
            )
            receivedPopChallenges.size shouldBe 2
            receivedPopChallenges shouldBe issuedAttestationChallenges
        }
    }

    test("retries PAR with the DPoP nonce from the error response") {
        with(AuthorizationServerFixture(requirePAR = true)) {
            http.execute(
                client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
            )

            // The AS mandates a nonce at PAR (RFC 9449 8.), and the client has none for the first request
            val parDpopNonces = http.sent.filterIsInstance<ProtocolRequest.PushedAuthorization>()
                .map { it.toRequestInfo().dpop.shouldNotBeNull().payload.nonce }
            parDpopNonces.size shouldBe 2
            parDpopNonces.first() shouldBe null
            parDpopNonces.last().shouldNotBeNull()
        }
    }

    test("fetches a fresh attestation challenge for every request") {
        with(AuthorizationServerFixture(requirePAR = true)) {
            authorizationCodeFlow()

            // A challenge is single-use on the server, so PAR and token must not share one
            receivedPopChallenges shouldBe issuedAttestationChallenges
            receivedPopChallenges.distinct() shouldBe receivedPopChallenges
        }
    }

    test("retries PAR once with attestation challenge from error response") {
        with(
            AuthorizationServerFixture(
                requirePAR = true,
                serveChallengeEndpoint = false,
                requireChallengeRetry = true,
            )
        ) {
            http.execute(
                client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
            )

            http.sent.kinds() shouldBe listOf("AttestationChallenge", "PushedAuthorization(0)", "PushedAuthorization(1)")
            receivedPopChallenges shouldBe listOf(null, issuedAttestationChallenges.single())
        }
    }

    /**
     * DPoP combined mode, i.e. one DPoP proof also serving as the Client Attestation PoP, from sections 5.2 and 7.3
     * of [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     */
    val combinedMode = setOf(ClientAttestationPopMethod.DpopCombined)

    suspend fun AuthorizationServerFixture.firstPushedAuthorizationRequest() = http.firstRequest<ProtocolRequest.PushedAuthorization>(
        client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
    ).toRequestInfo()

    test("combined mode sends attestation and DPoP proof, but no dedicated PoP") {
        with(AuthorizationServerFixture(requirePAR = true, popMethods = combinedMode, useSingleKey = true)) {
            val request = firstPushedAuthorizationRequest()

            request.clientAttestation.shouldNotBeNull()
            request.dpop.shouldNotBeNull()
            // 5.2: the DPoP proof replaces the dedicated PoP, it does not accompany it
            request.clientAttestationPop.shouldBeNull()
        }
    }

    test("combined mode signs the DPoP proof with the attested key") {
        with(AuthorizationServerFixture(requirePAR = true, popMethods = combinedMode, useSingleKey = true)) {
            val request = firstPushedAuthorizationRequest()
            val attestedKey = request.clientAttestation.shouldNotBeNull()
                .payload.confirmationClaim.shouldNotBeNull()
                .jsonWebKey.shouldNotBeNull()
            val dpopKey = request.dpop.shouldNotBeNull().jws.jwsHeader.jsonWebKey.shouldNotBeNull()

            // Without this the DPoP proof says nothing about possession of the attested key
            dpopKey.jwkThumbprint shouldBe attestedKey.jwkThumbprint
        }
    }

    test("combined mode carries the attestation challenge as the DPoP nonce") {
        with(AuthorizationServerFixture(requirePAR = true, popMethods = combinedMode, useSingleKey = true)) {
            val request = firstPushedAuthorizationRequest()

            http.sent.kinds() shouldBe listOf("AttestationChallenge")
            request.dpop.shouldNotBeNull().payload.nonce shouldBe issuedAttestationChallenges.single()
        }
    }

    test("combined mode completes the authorization code flow") {
        with(AuthorizationServerFixture(requirePAR = true, popMethods = combinedMode, useSingleKey = true)) {
            authorizationCodeFlow().params.accessToken.shouldNotBeNull()
        }
    }

    test("combined mode fails before sending when the attested key is not the DPoP key") {
        with(
            AuthorizationServerFixture(
                requirePAR = true,
                popMethods = combinedMode,
                useSingleKey = false, // independent DPoP key cannot prove possession of the attested key
            )
        ) {
            shouldThrow<IllegalArgumentException> {
                http.execute(
                    client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
                )
            }

            // A request that cannot possibly authenticate must not be sent at all
            http.sent.shouldBeEmpty()
        }
    }

    test("combined mode fails before sending when the AS advertises no usable DPoP algorithm") {
        with(
            AuthorizationServerFixture(
                requirePAR = true,
                popMethods = combinedMode,
                dpopAlgorithms = setOf(JwsAlgorithm.Signature.ES512), // client keys are ES256
                useSingleKey = true,
            )
        ) {
            shouldThrow<IllegalArgumentException> {
                http.execute(
                    client.startAuthorization(metadata(), authorizationService.publicContext, scope = requestedScope)
                )
            }

            // Combined mode without a DPoP proof is not a mode, so degrading silently must not happen
            http.sent.shouldBeEmpty()
        }
    }

    test("normal mode is preferred when the AS advertises both auth methods") {
        with(
            AuthorizationServerFixture(
                requirePAR = true,
                popMethods = setOf(ClientAttestationPopMethod.AttestationPopJwt, ClientAttestationPopMethod.DpopCombined),
                useSingleKey = false,
            )
        ) {
            val request = firstPushedAuthorizationRequest()
            val attestedKey = request.clientAttestation.shouldNotBeNull()
                .payload.confirmationClaim.shouldNotBeNull()
                .jsonWebKey.shouldNotBeNull()
            val dpop = request.dpop.shouldNotBeNull()

            request.clientAttestationPop.shouldNotBeNull()
            dpop.payload.nonce.shouldBeNull()
            dpop.jws.jwsHeader.jsonWebKey.shouldNotBeNull().jwkThumbprint shouldNotBe attestedKey.jwkThumbprint
        }
    }

    test("no attestation headers when the AS advertises no attestation auth method") {
        with(AuthorizationServerFixture(requirePAR = false, popMethods = null)) {
            val request = http.firstRequest<ProtocolRequest.Token>(client.preAuthTokenRequest(metadata()))
                .toRequestInfo()

            http.sent.shouldBeEmpty()
            request.clientAttestation.shouldBeNull()
            request.clientAttestationPop.shouldBeNull()
        }
    }

    test("uses attestation challenge from PAR response for token request") {
        with(AuthorizationServerFixture(requirePAR = true, provideChallengeOnParSuccess = true)) {
            authorizationCodeFlow()

            receivedPopChallenges shouldBe issuedAttestationChallenges
        }
    }
}
