package at.asitplus.wallet.lib.oauth2

import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferGrants
import at.asitplus.openid.CredentialOfferGrantsAuthCode
import at.asitplus.openid.CredentialOfferGrantsPreAuthCode
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.TokenTypes
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.WalletService
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Simple OAuth 2.0 client to authorize the client against an OAuth 2.0 Authorization Server and request tokens.
 *
 * Can be used in OID4VCI flows, e.g. [WalletService].
 */
class OAuth2Client(
    /**
     * Used to create [AuthenticationRequestParameters], [TokenRequestParameters] and
     * [at.asitplus.openid.CredentialRequestProofContainer], typically a URI.
     */
    val clientId: String = "https://wallet.a-sit.at/app",
    /**
     * Used to create [AuthenticationRequestParameters] and [TokenRequestParameters].
     */
    val redirectUrl: String = "$clientId/callback",
    /**
     * Used to store the code, associated to the state, to first send [AuthenticationRequestParameters.codeChallenge],
     * and then [TokenRequestParameters.codeVerifier], see [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).
     */
    private val stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
    /** Set this variable to use JAR (JWT-secured authorization requests, RFC 9101), as mandated by OpenID4VC HAIP. */
    val signPushedAuthorizationRequest: SignJwtFun<AuthenticationRequestParameters>? =
        SignJwt(EphemeralKeyWithSelfSignedCert(), JwsHeaderCertOrJwk()),
    private val randomSource: RandomSource = RandomSource.Default
) {

    /**
     * Send the result as parameters to the server at [OAuth2AuthorizationServerMetadata.authorizationEndpoint].
     * Use POST if [OAuth2AuthorizationServerMetadata.pushedAuthorizationRequestEndpoint] is available.
     *
     * Wraps the actual authorization request in a pushed authorization request (i.e. the `request` property),
     * if the [signPushedAuthorizationRequest] is available.
     *
     * Sample ktor code for GET:
     * ```
     * val authnRequest = client.createAuthRequest(...)
     * httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * ```
     *
     * Sample ktor code for POST:
     * ```
     * val authnRequest = client.createAuthRequest(...)
     * httpClient.submitForm(
     *     url = issuerMetadata.pushedAuthorizationRequestEndpoint,
     *     formParameters = parameters {
     *         authnRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * ```
     *
     * @param state to keep internal state in further requests
     * @param scope in OID4VCI flows the value `scope` from [IssuerMetadata.supportedCredentialConfigurations]
     * @param authorizationDetails from RFC 9396 OAuth 2.0 Rich Authorization Requests
     * @param resource from RFC 8707 Resource Indicators for OAuth 2.0, in OID4VCI flows the value
     * of [IssuerMetadata.credentialIssuer]
     * @param issuerState for OID4VCI flows the value from [CredentialOfferGrantsAuthCode.issuerState]
     */
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null,
        issuerState: String? = null
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        authorizationDetails = authorizationDetails,
        scope = scope,
        resource = resource,
        issuerState = issuerState,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256
    )

    suspend fun createAuthRequestJar(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null,
        issuerState: String? = null,
        audience: String? = null,
    ) = signPushedAuthorizationRequest?.let { signJwtFun ->
        createAuthRequest(state, authorizationDetails, scope, resource, issuerState).let {
            JarRequestParameters(
                clientId = clientId,
                request = signPushedAuthorizationRequest(
                    JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
                    it.copy(
                        audience = audience,
                        issuer = it.clientId,
                    ),
                    AuthenticationRequestParameters.serializer(),
                ).getOrThrow().serialize()
            )
        }
    } ?: throw Exception("SignPushedAuthorizationRequest is null.")

    /**
     * Send the result as parameters to the server at [OAuth2AuthorizationServerMetadata.authorizationEndpoint].
     * Use this method if the previous authn request was sent as a pushed authorization request (RFC 9126),
     * and the server has answered with [PushedAuthenticationResponseParameters].
     *
     * @param parResponse response from the AS to the PAR request
     */
    suspend fun createAuthRequestAfterPar(
        parResponse: PushedAuthenticationResponseParameters,
    ) = JarRequestParameters(
        clientId = clientId,
        requestUri = parResponse.requestUri,
    )

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun generateCodeVerifier(state: String): String =
        randomSource.nextBytes(32).toHexString(HexFormat.Default)
            .also { stateToCodeStore.put(state, it) }
            .encodeToByteArray().sha256().encodeToString(Base64UrlStrict)

    /**
     * Authorization input used to request or refresh an OAuth2 access token.
     * Use to indicate which grant or token exchange flow should be performed.
     */
    sealed class AuthorizationForToken {
        /** Authorization code from an actual OAuth2 Authorization Server, or [SimpleAuthorizationService.authorize]. */
        data class Code(val code: String) : AuthorizationForToken()

        /** Refresh token for obtaining a new access token, see [TokenResponseParameters.refreshToken]. */
        data class RefreshToken(val refreshToken: String) : AuthorizationForToken()

        /**
         * Pre-auth code from [CredentialOfferGrantsPreAuthCode.preAuthorizedCode] in
         * [CredentialOfferGrants.preAuthorizedCode] in [CredentialOffer.grants],
         * optionally with a [transactionCode] which is transmitted out-of-band, and may be entered by the user.
         */
        data class PreAuthCode(
            val preAuthorizedCode: String,
            val transactionCode: String? = null,
        ) : AuthorizationForToken()

        /** Use a [subjectToken] provided by another entity to perform Token Exchange. */
        data class TokenExchange(
            val subjectToken: String,
        ) : AuthorizationForToken()
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at
     * [OAuth2AuthorizationServerMetadata.tokenEndpoint].
     *
     * Sample ktor code for authorization code:
     * ```
     * val authnRequest = client.createAuthRequest(requestOptions)
     * val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
     * val code = authnResponse.params.code
     * val tokenRequest = client.createTokenRequestParameters(state, AuthorizationForToken.Code(code))
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Sample ktor code for pre-authn code:
     * ```
     * val preAuth = credentialOffer.grants.preAuthorizedCode
     * val transactionCode = "..." // get from user input
     * val authorization = WalletService.AuthorizationForToken.PreAuthCode(preAuth, transactionCode)
     * val tokenRequest = client.createTokenRequestParameters(state, authorization)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Be sure to include a DPoP header if [OAuth2AuthorizationServerMetadata.dpopSigningAlgValuesSupported] is set,
     * see [at.asitplus.wallet.lib.oidvci.BuildDPoPHeader].
     *
     * @param state to keep internal state in further requests
     * @param authorization for the token endpoint
     * @param authorizationDetails from RFC 9396 OAuth 2.0 Rich Authorization Requests
     * @param scope in OID4VCI flows the value `scope` from [IssuerMetadata.supportedCredentialConfigurations]
     * @param resource from RFC 8707 Resource Indicators for OAuth 2.0, in OID4VCI flows the value
     * of [IssuerMetadata.credentialIssuer]
     */
    suspend fun createTokenRequestParameters(
        authorization: AuthorizationForToken,
        state: String? = null,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            codeVerifier = state?.let { stateToCodeStore.remove(it) },
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = authorizationDetails,
            scope = scope,
            resource = resource,
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE,
            preAuthorizedCode = authorization.preAuthorizedCode,
            transactionCode = authorization.transactionCode,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = authorizationDetails,
            scope = scope,
            resource = resource,
        )

        is AuthorizationForToken.RefreshToken -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_REFRESH_TOKEN,
            refreshToken = authorization.refreshToken,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = authorizationDetails,
            scope = scope,
            resource = resource,
        )

        is AuthorizationForToken.TokenExchange -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_TOKEN_EXCHANGE,
            subjectToken = authorization.subjectToken,
            subjectTokenType = TokenTypes.ACCESS_TOKEN,
            requestedTokenType = TokenTypes.ACCESS_TOKEN,
            redirectUrl = redirectUrl,
            clientId = clientId,
            scope = scope,
            resource = resource,
        )
    }

}
