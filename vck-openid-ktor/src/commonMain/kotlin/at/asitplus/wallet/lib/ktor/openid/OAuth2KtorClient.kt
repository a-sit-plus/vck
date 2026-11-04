package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenIntrospectionRequest
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient
import at.asitplus.wallet.lib.oauth2.TokenResponseWithDpopNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import com.benasher44.uuid.uuid4
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.json.JsonObject

/**
 * Implements the client side of OAuth2 with ktor, by sending the requests of [OAuth2ProtocolClient], which implements
 * the protocol.
 *
 * Supported features:
 *  * Token requests and responses
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 *  * [JSON Web Token (JWT) Response for OAuth Token Introspection](https://datatracker.ietf.org/doc/html/rfc9701)
 *  * [EUDI TS3 Wallet Unit Attestation 1.5.2](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
class OAuth2KtorClient private constructor(
    /** Sends the requests, configured not to follow redirects. */
    private val client: HttpClient,
    /**
     * Implements the protocol; this class only sends its requests. Internal only to wire protocol clients that need to
     * share its state, i.e. the DPoP nonces, see [OpenId4VciKtorClient].
     */
    internal val protocolClient: OAuth2ProtocolClient,
) {

    /**
     * @param httpClient the app's ktor client, i.e. with its engine, cookie storage (advised to be persistent, to keep
     * the session at the authorization server alive after receiving the auth code) and logging. This class sends its
     * requests with a copy that does not follow redirects (see [HttpClient.config]), setting content type and status
     * handling per request. Plugins must not re-send requests or react to error statuses, e.g. by caching failures:
     * retries after a `use_dpop_nonce` error re-send the same request, and DPoP proofs and client attestation PoPs are
     * single-use.
     * @param oAuth2Client implements the OAuth 2.0 protocol, `redirectUrl` needs to be registered by the OS for this
     * application, so redirection back from browser works
     * @param clientAttestation authenticates the client with
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html),
     * e.g. with a Wallet Instance Attestation (WIA), or `null` to not use it
     * @param dpopKeyMaterial the key material the access tokens and refresh tokens get bound to, used for calculating
     * DPoP proofs; by default the key of [clientAttestation], as
     * [EUDI TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
     * requires, so that refresh tokens remain usable after the app restarts, else an ephemeral key
     * @param randomSource source for random bytes, i.e., nonces for proof-of-possession of key material for
     * sender-constrained tokens
     * @param verifyTokenIntrospectionJwt verifies the signature of JWT responses of token introspection (RFC 9701)
     * against the keys of the authorization server; when set, token introspection requests and accepts only JWT
     * responses, when `null` (the default) plain JSON responses
     */
    constructor(
        httpClient: HttpClient,
        oAuth2Client: OAuth2Client,
        clientAttestation: ClientAttestation? = null,
        dpopKeyMaterial: KeyMaterial = clientAttestation?.keyMaterial ?: EphemeralKeyWithoutCert(),
        randomSource: RandomSource = RandomSource.Secure,
        verifyTokenIntrospectionJwt: VerifyJwsObjectFun? = null,
    ) : this(
        client = httpClient.config { followRedirects = false },
        protocolClient = OAuth2ProtocolClient(
            oAuth2Client = oAuth2Client,
            clientAttestation = clientAttestation,
            dpopKeyMaterial = dpopKeyMaterial,
            randomSource = randomSource,
            verifyTokenIntrospectionJwt = verifyTokenIntrospectionJwt,
        ),
    )

    /**
     * Implements OAuth2 protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works
     */
    val oAuth2Client: OAuth2Client
        get() = protocolClient.oAuth2Client

    /** Authenticates the client with OAuth 2.0 Attestation-Based Client Authentication, if not `null`. */
    val clientAttestation: ClientAttestation?
        get() = protocolClient.clientAttestation

    /** Sends all requests of [exchange] with this client, sharing its cookies, and returns its result. */
    internal suspend fun <T> execute(exchange: HttpExchange<T>): T = client.execute(exchange)

    /** Loads the metadata of [authorizationServer], see [OAuth2ProtocolClient.loadAuthorizationServerMetadata]. */
    internal suspend fun loadAuthorizationServerMetadata(authorizationServer: String): OAuth2AuthorizationServerMetadata =
        execute(protocolClient.loadAuthorizationServerMetadata(authorizationServer))

    /** Loads the user info with the access token from [tokenResponse], see [OAuth2ProtocolClient.userInfoRequest]. */
    internal suspend fun requestUserInfo(userInfoEndpoint: String, tokenResponse: TokenResponseParameters): JsonObject =
        execute(protocolClient.userInfoRequest(userInfoEndpoint, tokenResponse))

    /**
     * Uses a pre-authorized code from the authorization server to request an access token.
     */
    suspend fun requestTokenWithPreAuthorizedCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        preAuthorizedCode: String,
        transactionCode: String?,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        execute(
            protocolClient.requestTokenWithPreAuthorizedCode(
                oauthMetadata = oauthMetadata,
                authorizationServer = authorizationServer,
                preAuthorizedCode = preAuthorizedCode,
                transactionCode = transactionCode,
                scope = scope,
                authorizationDetails = authorizationDetails,
                issuerMetadata = issuerMetadata,
            )
        )
    }

    /**
     * Uses the auth code to request an access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * @param url the URL as it has been redirected back from the authorization server, i.e. containing param `code`
     */
    suspend fun requestTokenWithAuthCode(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        url: String,
        authorizationServer: String,
        state: String,
        scope: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        execute(
            protocolClient.requestTokenWithAuthCode(
                oauthMetadata = oauthMetadata,
                url = url,
                authorizationServer = authorizationServer,
                state = state,
                scope = scope,
                authorizationDetails = authorizationDetails,
                issuerMetadata = issuerMetadata,
            )
        )
    }

    /**
     * Uses the refresh token to request a new access token.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     */
    suspend fun requestTokenWithRefreshToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        credentialIssuer: String,
        refreshToken: String,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        execute(
            protocolClient.requestTokenWithRefreshToken(
                oauthMetadata = oauthMetadata,
                credentialIssuer = credentialIssuer,
                refreshToken = refreshToken,
                scope = scope,
                authorizationDetails = authorizationDetails,
                issuerMetadata = issuerMetadata,
            )
        )
    }

    /**
     * Uses an access token from another client to request a new access token,
     * see [RFC8693 OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).
     */
    suspend fun requestTokenWithTokenExchange(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        subjectToken: String,
        resource: String?,
        issuerMetadata: IssuerMetadata? = null,
    ): KmmResult<TokenResponseWithDpopNonce> = catching {
        execute(
            protocolClient.requestTokenWithTokenExchange(
                oauthMetadata = oauthMetadata,
                authorizationServer = authorizationServer,
                subjectToken = subjectToken,
                resource = resource,
                issuerMetadata = issuerMetadata,
            )
        )
    }

    /**
     * Builds the authorization request ([AuthenticationRequestParameters]) to start authentication at the
     * authorization server.
     *
     * Prefers building the authn request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Uses Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) if advised
     * by the authorization server.
     *
     * Clients need to continue the process (after getting back from the browser) with [requestTokenWithAuthCode].
     */
    suspend fun startAuthorization(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        authorizationServer: String,
        state: String = uuid4().toString(),
        issuerState: String? = null,
        authorizationDetails: Set<OpenIdAuthorizationDetails>? = null,
        scope: String? = null,
        issuerMetadata: IssuerMetadata? = null
    ): KmmResult<OAuth2ProtocolClient.OpenUrlForAuthnRequest> = catching {
        execute(
            protocolClient.startAuthorization(
                oauthMetadata = oauthMetadata,
                authorizationServer = authorizationServer,
                state = state,
                issuerState = issuerState,
                authorizationDetails = authorizationDetails,
                scope = scope,
                issuerMetadata = issuerMetadata,
            )
        )
    }

    /**
     * Calls the token introspection endpoint ([OAuth2AuthorizationServerMetadata.introspectionEndpoint])
     * to check whether the given token is active, returns the response on success, otherwise throws [InvalidToken].
     */
    suspend fun callTokenIntrospection(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        request: TokenIntrospectionRequest,
        popAudience: String,
        issuerMetadata: IssuerMetadata? = null,
    ): TokenIntrospectionResponse = execute(
        protocolClient.callTokenIntrospection(
            oauthMetadata = oauthMetadata,
            request = request,
            popAudience = popAudience,
            issuerMetadata = issuerMetadata,
        )
    )

    /**
     * Sets the appropriate headers when accessing [resourceUrl], by reading data from [tokenResponse],
     * i.e. [HttpHeaders.Authorization] and probably `DPoP`, see [OAuth2ProtocolClient.accessTokenHeaders].
     */
    suspend fun applyToken(
        tokenResponse: TokenResponseParameters,
        resourceUrl: String,
        httpMethod: HttpMethod,
        dpopNonce: String? = null,
    ): HttpRequestBuilder.() -> Unit {
        val tokenHeaders = protocolClient.accessTokenHeaders(tokenResponse, resourceUrl, httpMethod, dpopNonce)
        return {
            headers {
                appendAll(tokenHeaders)
            }
        }
    }
}
