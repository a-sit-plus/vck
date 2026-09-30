package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.oauth2.AuthorizationServerFixture
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient
import at.asitplus.wallet.lib.oauth2.TokenResponseWithDpopNonce
import at.asitplus.wallet.lib.oauth2.jsonResponse
import at.asitplus.wallet.lib.oauth2.kinds
import at.asitplus.wallet.lib.oauth2.path
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.oauth2.toRequestInfo
import at.asitplus.wallet.lib.openid.DummyUserProvider
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val OpenId4VciProtocolClientTest by matrixSuite {

    fun AuthorizationServerFixture.vciClient() = OpenId4VciProtocolClient(
        oid4vciService = WalletService(clientId = clientId),
        oauth2Client = client,
    )

    /** The SD-JWT format of [AtomicAttribute2023], which [at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider] issues. */
    fun OpenId4VciProtocolClient.selectFormat(fixture: AuthorizationServerFixture): SupportedCredentialFormat =
        oid4vciService.selectSupportedCredentialFormat(
            WalletService.RequestOptions(AtomicAttribute2023, SD_JWT),
            fixture.credentialIssuer.metadata,
        ).shouldNotBeNull()

    /** Requests a token with a pre-authorized code, as issued by the fixture's authorization server. */
    suspend fun AuthorizationServerFixture.preAuthorizedToken(
        format: SupportedCredentialFormat,
    ): TokenResponseWithDpopNonce = http.execute(
        client.requestTokenWithPreAuthorizedCode(
            oauthMetadata = metadata(),
            authorizationServer = authorizationService.publicContext,
            preAuthorizedCode = authorizationService.providePreAuthorizedCode(DummyUserProvider.user),
            transactionCode = null,
            scope = format.scope,
            authorizationDetails = setOf(),
        )
    )

    /** Requests nonce and credentials with [token], as the last part of every issuance flow. */
    suspend fun AuthorizationServerFixture.requestCredentials(
        vci: OpenId4VciProtocolClient,
        token: TokenResponseWithDpopNonce,
        format: SupportedCredentialFormat,
    ): Collection<Holder.StoreCredentialInput> {
        val issuerMetadata = credentialIssuer.metadata
        val clientNonce = vci.nonceRequest(issuerMetadata)?.let { http.execute(it) }
        val scheme = vci.resolveCredentialScheme(format).shouldNotBeNull()
        return vci.oid4vciService.createCredential(
            tokenResponse = token.params,
            metadata = issuerMetadata,
            credentialFormat = format,
            clientNonce = clientNonce,
            previouslyRequestedScope = format.scope,
        ).getOrThrow().flatMap {
            http.execute(vci.credentialRequest(it, issuerMetadata, token.params, format, scheme))
        }
    }

    // Step sequences, see the KDoc of the methods of OpenId4VciProtocolClient

    test("issuer metadata comes from the well-known path") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val issuerMetadata = http.execute(vciClient().loadIssuerMetadata(credentialIssuer.metadata.credentialIssuer))

            issuerMetadata.credentialEndpointUrl shouldBe credentialIssuer.metadata.credentialEndpointUrl
            http.sent.kinds() shouldBe listOf("CredentialIssuerMetadata")
            http.sent.single().http.path shouldBe "/.well-known/openid-credential-issuer"
        }
    }

    test("parsed credential metadata lists every credential configuration") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val issuerMetadata = credentialIssuer.metadata

            vciClient().parseCredentialMetadata(issuerMetadata).getOrThrow()
                .map { it.credentialIdentifier }.toSet() shouldBe issuerMetadata.supportedCredentialConfigurations.keys
        }
    }

    test("authorization server is the first one listed, or the credential issuer itself") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val vci = vciClient()
            val issuerMetadata = credentialIssuer.metadata

            vci.selectAuthorizationServer(
                issuerMetadata.copy(authorizationServers = setOf("https://as1.example.com", "https://as2.example.com")),
                "https://issuer.example.com",
            ) shouldBe "https://as1.example.com"
            vci.selectAuthorizationServer(issuerMetadata.copy(authorizationServers = null), "https://issuer.example.com")
                .shouldBe("https://issuer.example.com")
        }
    }

    test("nonce request yields a c_nonce, or is absent without a nonce endpoint") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val vci = vciClient()

            http.execute(vci.nonceRequest(credentialIssuer.metadata).shouldNotBeNull()).shouldNotBeBlank()
            vci.nonceRequest(credentialIssuer.metadata.copy(nonceEndpointUrl = null)).shouldBeNull()
            http.sent.kinds() shouldBe listOf("Nonce")
        }
    }

    test("credential request retries once with the DPoP nonce, then fails") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val vci = vciClient()
            val format = vci.selectFormat(this)
            val token = TokenResponseParameters(
                accessToken = uuid4().toString(),
                tokenType = TOKEN_TYPE_DPOP,
                scope = format.scope,
            )
            val request = vci.oid4vciService.createCredential(
                tokenResponse = token,
                metadata = credentialIssuer.metadata,
                credentialFormat = format,
                clientNonce = uuid4().toString(),
            ).getOrThrow().shouldBeSingleton().first()
            val resourceServerNonceError = ReceivedHttpResponse(
                status = HttpStatusCode.Unauthorized,
                headers = headers {
                    append(HttpHeaders.WWWAuthenticate, "DPoP error=\"$USE_DPOP_NONCE\"")
                    append(HttpHeaders.DPoPNonce, "n1")
                },
                body = "",
            )
            val scriptedHttp = FakeHttpStack(scripted(resourceServerNonceError, resourceServerNonceError))

            shouldThrow<HttpErrorResponseException> {
                scriptedHttp.execute(
                    vci.credentialRequest(
                        request = request,
                        issuerMetadata = credentialIssuer.metadata,
                        tokenResponse = token,
                        credentialFormat = format,
                        credentialScheme = vci.resolveCredentialScheme(format).shouldNotBeNull(),
                    )
                )
            }

            scriptedHttp.sent.kinds() shouldBe listOf("Credential(0)", "Credential(1)")
            scriptedHttp.sent[1].toRequestInfo().dpop.shouldNotBeNull().payload.nonce shouldBe "n1"
        }
    }

    // Complete issuance flows, without ktor

    test("pre-authorized code flow with DPoP and client attestation") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val vci = vciClient()
            val issuerMetadata = http.execute(vci.loadIssuerMetadata(credentialIssuer.metadata.credentialIssuer))
            val format = vci.selectFormat(this)
            http.execute(
                client.loadAuthorizationServerMetadata(
                    vci.selectAuthorizationServer(issuerMetadata, issuerMetadata.credentialIssuer)
                )
            ).issuer shouldBe authorizationService.publicContext

            val credentials = requestCredentials(vci, preAuthorizedToken(format), format)

            credentials.shouldBeSingleton().first().shouldBeInstanceOf<Holder.StoreCredentialInput.SdJwt>()
            // The AS mandates a DPoP nonce (RFC 9449 8.), which the client can only learn from the rejected first
            // token request; the retry needs a fresh attestation challenge, as challenges are single-use
            http.sent.kinds() shouldBe listOf(
                "CredentialIssuerMetadata",
                "AuthorizationServerMetadata",
                "AttestationChallenge",
                "Token(0)",
                "AttestationChallenge",
                "Token(1)",
                "Nonce",
                "Credential(0)",
            )
        }
    }

    test("authorization code flow with PAR, DPoP and client attestation") {
        with(AuthorizationServerFixture(requirePAR = true)) {
            val vci = vciClient()
            val format = vci.selectFormat(this)
            val authorization = http.execute(
                client.startAuthorization(
                    oauthMetadata = metadata(),
                    authorizationServer = authorizationService.publicContext,
                    scope = format.scope,
                    issuerMetadata = credentialIssuer.metadata,
                )
            )
            val token = http.execute(
                client.requestTokenWithAuthCode(
                    oauthMetadata = metadata(),
                    url = authorize(authorization.url),
                    authorizationServer = authorizationService.publicContext,
                    state = authorization.state,
                    scope = format.scope,
                    issuerMetadata = credentialIssuer.metadata,
                )
            )

            requestCredentials(vci, token, format).shouldNotBeEmpty()
            http.sent.kinds() shouldBe listOf(
                "AttestationChallenge",
                "PushedAuthorization(0)",
                "AttestationChallenge",
                "PushedAuthorization(1)",
                "AttestationChallenge",
                "Token(0)",
                "Nonce",
                "Credential(0)",
            )
        }
    }

    // DPoP nonces belong to the server that issued them

    /**
     * [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9): nonces of an authorization server and a
     * resource server "are different and should not be confused with one another", even on the same origin.
     */
    test("nonces of the authorization server and the credential issuer are kept apart on the same origin") {
        with(AuthorizationServerFixture(requirePAR = false)) {
            val oauth2Client = OAuth2ProtocolClient(oAuth2Client = OAuth2Client(clientId = clientId))
            val vci = OpenId4VciProtocolClient(WalletService(clientId = clientId), oauth2Client)
            val format = vci.selectFormat(this)
            val issuerMetadata = credentialIssuer.metadata
            val origin = Url(issuerMetadata.credentialEndpointUrl).let { "${it.protocol.name}://${it.host}" }
            val oauthMetadata = OAuth2AuthorizationServerMetadata(
                issuer = origin,
                tokenEndpoint = "$origin/token",
                dpopSigningAlgValuesSupportedStrings = setOf(JwsAlgorithm.Signature.ES256.identifier),
            )
            val scriptedHttp = FakeHttpStack(
                scripted(
                    jsonResponse(
                        TokenResponseParameters(
                            accessToken = uuid4().toString(),
                            tokenType = TOKEN_TYPE_DPOP,
                            refreshToken = uuid4().toString(),
                            scope = format.scope,
                        )
                    ) { append(HttpHeaders.DPoPNonce, "as-nonce") },
                    jsonResponse(ClientNonceResponse(clientNonce = uuid4().toString())) {
                        append(HttpHeaders.DPoPNonce, "rs-nonce")
                    },
                )
            )
            val token = scriptedHttp.execute(
                oauth2Client.requestTokenWithPreAuthorizedCode(
                    oauthMetadata = oauthMetadata,
                    authorizationServer = origin,
                    preAuthorizedCode = uuid4().toString(),
                    transactionCode = null,
                    scope = format.scope,
                    authorizationDetails = setOf(),
                )
            )
            val clientNonce = scriptedHttp.execute(vci.nonceRequest(issuerMetadata).shouldNotBeNull())
            val request = vci.oid4vciService.createCredential(
                token.params, issuerMetadata, format, clientNonce, previouslyRequestedScope = format.scope,
            ).getOrThrow().first()

            val credentialRequest = scriptedHttp.firstRequest<ProtocolRequest.Credential>(
                vci.credentialRequest(
                    request, issuerMetadata, token.params, format, vci.resolveCredentialScheme(format).shouldNotBeNull()
                )
            )
            val refreshTokenRequest = scriptedHttp.firstRequest<ProtocolRequest.Token>(
                oauth2Client.requestTokenWithRefreshToken(
                    oauthMetadata = oauthMetadata,
                    credentialIssuer = issuerMetadata.credentialIssuer,
                    refreshToken = token.params.refreshToken.shouldNotBeNull(),
                    scope = format.scope,
                    authorizationDetails = setOf(),
                )
            )

            credentialRequest.toRequestInfo().dpop.shouldNotBeNull().payload.nonce shouldBe "rs-nonce"
            refreshTokenRequest.toRequestInfo().dpop.shouldNotBeNull().payload.nonce shouldBe "as-nonce"
        }
    }

    /** [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9): nonces are only accepted by the server that issued them. */
    test("credential request does not use the DPoP nonce of the authorization server") {
        with(
            AuthorizationServerFixture(
                requirePAR = false,
                credentialIssuerPublicContext = "https://credentials.example.com",
            )
        ) {
            val vci = vciClient()
            val format = vci.selectFormat(this)
            val token = preAuthorizedToken(format)
            token.dpopNonce.shouldNotBeNull()
            // a nonce endpoint would supply the credential issuer's own DPoP nonce
            val issuerMetadata = credentialIssuer.metadata.copy(nonceEndpointUrl = null)
            val request = vci.oid4vciService.createCredential(
                token.params, issuerMetadata, format, previouslyRequestedScope = format.scope,
            ).getOrThrow().first()

            val credentialRequest = http.firstRequest<ProtocolRequest.Credential>(
                vci.credentialRequest(request, issuerMetadata, token.params, format, vci.resolveCredentialScheme(format).shouldNotBeNull())
            )

            credentialRequest.http.url shouldBe "https://credentials.example.com/credential"
            credentialRequest.toRequestInfo().dpop.shouldNotBeNull().payload.nonce.shouldBeNull()
        }
    }

    // Persisted by wallets, e.g. in the provisioning context kept during the browser round trip

    test("credential identifier info keeps its serialized form") {
        val json = """
            {
              "issuerMetadata": {
                "credential_issuer": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "credential_configurations_supported": {
                  "pid": { "format": "dc+sd-jwt", "vct": "urn:eudi:pid:1" }
                }
              },
              "credentialIdentifier": "pid",
              "supportedCredentialFormat": { "format": "dc+sd-jwt", "vct": "urn:eudi:pid:1" }
            }
        """.trimIndent()

        joseCompliantSerializer.decodeFromString<CredentialIdentifierInfo>(json).apply {
            credentialIdentifier shouldBe "pid"
            issuerMetadata.credentialIssuer shouldBe "https://issuer.example.com"
            supportedCredentialFormat shouldBe issuerMetadata.supportedCredentialConfigurations["pid"]
        }
    }
}
