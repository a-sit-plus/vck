package at.asitplus.wallet.lib.oauth2

import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants.ClientAttestationPopMethod
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersSerializer
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.decodeFromFormUrlEncoded
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oidvci.BuildClientAttestationJwt
import at.asitplus.wallet.lib.oidvci.CredentialAuthorizationServiceStrategy
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import at.asitplus.wallet.lib.openid.DummyOAuth2IssuerCredentialDataProvider
import at.asitplus.wallet.lib.openid.DummyUserProvider
import io.kotest.matchers.nulls.shouldNotBeNull
import io.ktor.http.*

/**
 * An authorization server (with attestation-based client authentication and DPoP) and a credential issuer (issuing
 * credentials from [DummyOAuth2IssuerCredentialDataProvider]), reachable through [http], plus an
 * [OAuth2ProtocolClient] to use them.
 */
class AuthorizationServerFixture(
    requestObjectSigningAlgorithms: Set<JwsAlgorithm.Signature>? = setOf(JwsAlgorithm.Signature.ES256),
    requirePAR: Boolean,
    captureAttestationInput: ((OAuth2ProtocolClient.LoadInstanceAttestationInput) -> Unit)? = null,
    private val serveChallengeEndpoint: Boolean = true,
    requireChallengeRetry: Boolean = false,
    popMethods: Set<ClientAttestationPopMethod>? = setOf(ClientAttestationPopMethod.AttestationPopJwt),
    dpopAlgorithms: Set<JwsAlgorithm.Signature> = setOf(JwsAlgorithm.Signature.ES256),
    /** DPoP combined mode has a single key: the attested key is also the DPoP key. */
    useSingleKey: Boolean = false,
    /** Origin of the credential issuer, which may differ from the one of the authorization server. */
    credentialIssuerPublicContext: String = "https://issuer.example.com",
) {
    val strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet)
    val requestedScope = strategy.validScopes().split(" ").first()
    val clientAuthKeyMaterial = EphemeralKeyWithoutCert()
    val clientId = "https://example.com/rp"

    // In DPoP combined mode the attestation challenge is carried in the DPoP proof's nonce, so both stores
    // must be the same instance for a challenge to be accepted as a DPoP nonce
    private val proofNonceService = DefaultNonceService()

    val authorizationService = SimpleAuthorizationService(
        strategy = strategy,
        publicContext = "https://issuer.example.com",
        authorizationEndpointPath = "/authorize",
        tokenEndpointPath = "/token",
        pushedAuthorizationRequestEndpointPath = "/par",
        clientAuthenticationService = popMethods?.let {
            AttestationBasedClientAuthenticationService(
                acceptedPopMethods = it,
                nonceService = proofNonceService,
            )
        } ?: NoopClientAuthenticationService,
        tokenService = TokenService.jwt(
            issueRefreshTokens = true,
            dpopNonceService = proofNonceService,
            verificationAlgorithms = dpopAlgorithms,
        ),
        requestObjectSigningAlgorithms = requestObjectSigningAlgorithms,
        requirePushedAuthorizationRequests = requirePAR,
    )

    val openId4VciServer = OpenId4VciServer(
        issuer = IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ),
        authorizationService = authorizationService,
        credentialSchemes = AttributeIndex.schemeSet,
        publicContext = credentialIssuerPublicContext,
    )

    /** Challenges from the challenge endpoint and from error responses. */
    val issuedAttestationChallenges = mutableListOf<String>()

    /** Fresh challenges from success responses of PAR and token endpoints. */
    val attestationChallengesOnSuccess = mutableListOf<String>()
    val receivedPopChallenges = mutableListOf<String?>()
    private var challengeRetryRequired = requireChallengeRetry

    val http = FakeHttpStack(::route)

    val client = OAuth2ProtocolClient(
        oAuth2Client = OAuth2Client(clientId = clientId),
        clientAttestation = ClientAttestation(clientAuthKeyMaterial) {
            captureAttestationInput?.invoke(it)
            catching {
                BuildClientAttestationJwt(
                    SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
                    clientId = clientId,
                    clientKey = clientAuthKeyMaterial.jsonWebKey
                )
            }
        },
        dpopKeyMaterial = if (useSingleKey) clientAuthKeyMaterial else EphemeralKeyWithoutCert(),
        randomSource = RandomSource.Default,
    )

    suspend fun metadata() = authorizationService.metadata()

    /** Simulates the browser: opens [authorizationUrl], and returns the redirect back to the client with the code. */
    suspend fun authorize(authorizationUrl: String): String {
        val parameters = Url(authorizationUrl).parameters.entries().associate { it.key to it.value.first() }
        val request: RequestParameters = RequestParametersSerializer.decodeFormParameters(parameters)
        return authorizationService.authorize(request) { catching { DummyUserProvider.user } }.getOrThrow()
            .toHttpResponse().headers[HttpHeaders.Location].shouldNotBeNull()
    }

    /** Runs the authorization code flow with PAR (if required), and returns the token response. */
    suspend fun authorizationCodeFlow() = client.startAuthorization(
        oauthMetadata = metadata(),
        authorizationServer = authorizationService.publicContext,
        scope = requestedScope,
    ).let { http.execute(it) }.let { authorization ->
        http.execute(
            client.requestTokenWithAuthCode(
                oauthMetadata = metadata(),
                url = authorize(authorization.url),
                authorizationServer = authorizationService.publicContext,
                state = authorization.state,
                scope = requestedScope,
                authorizationDetails = setOf(),
            )
        )
    }

    private suspend fun newAttestationChallenge(): String =
        authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull().attestationChallenge
            .also { issuedAttestationChallenges += it }

    private suspend fun route(request: PreparedHttpRequest): ReceivedHttpResponse = when {
        request.path == "/.well-known/oauth-authorization-server" -> metadata().toHttpResponse().received()

        request.path == "/.well-known/openid-credential-issuer" -> jsonResponse(openId4VciServer.metadata)

        request.path.startsWith("/nonce") -> openId4VciServer.nonceWithDpopNonce().getOrThrow().let { result ->
            jsonResponse(result.response) {
                append(HttpHeaders.CacheControl, "no-store")
                result.dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) }
            }
        }

        request.path.startsWith("/credential") -> openId4VciServer.credential(
            authorizationHeader = request.headers[HttpHeaders.Authorization].shouldNotBeNull(),
            params = OpenId4VciClient.CredentialRequest.parse(request.body.orEmpty()).getOrThrow(),
            credentialDataProvider = DummyOAuth2IssuerCredentialDataProvider,
            request = request.toRequestInfo(),
        ).fold(
            onSuccess = {
                when (it) {
                    is OpenId4VciServer.CredentialResponse.Plain -> jsonResponse(it.response)
                    is OpenId4VciServer.CredentialResponse.Encrypted -> ReceivedHttpResponse(
                        status = HttpStatusCode.OK,
                        headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JWT),
                        body = it.response.serialize(),
                    )
                }
            },
            onFailure = { it.toErrorResponse() },
        )

        request.path.startsWith("/challenge") && serveChallengeEndpoint -> {
            val response = authorizationService.attestationChallenge().getOrThrow().shouldNotBeNull()
            issuedAttestationChallenges += response.attestationChallenge
            response.toHttpResponse().received()
        }

        request.path.startsWith("/par") -> {
            receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
            if (challengeRetryRequired) {
                challengeRetryRequired = false
                // PAR mandates a fresh DPoP nonce, so the AS supplies it along with the rejection for the missing
                // attestation challenge, and a single retry carries both.
                OAuth2Exception.UseAttestationChallenge(newAttestationChallenge()).toHttpResponse().received()
                    .withHeader(HttpHeaders.DPoPNonce, authorizationService.getDpopNonce().shouldNotBeNull())
            } else {
                val authnRequest: RequestParameters =
                    RequestParametersSerializer.decodeFormParameters(request.formParameters())
                authorizationService.parWithDpopNonce(authnRequest, request.toRequestInfo()).fold(
                    onSuccess = { result ->
                        result.attestationChallenge?.let { attestationChallengesOnSuccess += it }
                        result.toHttpResponse().received()
                    },
                    onFailure = { it.toAuthorizationServerResponse() }
                )
            }
        }

        request.path.startsWith("/token") -> {
            receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
            val params = request.body.orEmpty().decodeFromFormUrlEncoded<TokenRequestParameters>()
            authorizationService.tokenWithDpopNonce(params, request.toRequestInfo()).fold(
                onSuccess = { result ->
                    result.attestationChallenge?.let { attestationChallengesOnSuccess += it }
                    result.toHttpResponse().received()
                },
                onFailure = { it.toAuthorizationServerResponse() },
            )
        }

        request.path.startsWith("/introspect") -> {
            receivedPopChallenges += request.toRequestInfo().clientAttestationPop?.payload?.challenge
            val params = request.body.orEmpty().decodeFromFormUrlEncoded<TokenIntrospectionRequest>()
            authorizationService.tokenIntrospection(params, request.toRequestInfo()).fold(
                onSuccess = { it.toHttpResponse().received() },
                onFailure = { it.toAuthorizationServerResponse() },
            )
        }

        else -> ReceivedHttpResponse(HttpStatusCode.NotFound, Headers.Empty, "")
    }
}
