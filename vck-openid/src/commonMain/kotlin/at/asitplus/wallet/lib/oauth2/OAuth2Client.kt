package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.buildDPoPHeader
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

/**
 * Simple OAuth 2.0 client to authorize the client against an OAuth 2.0 Authorization Server and request tokens.
 *
 * Can be used in OID4VCI flows, e.g. [WalletService].
 */
class OAuth2Client(
    /**
     * Used to create [AuthenticationRequestParameters], [TokenRequestParameters] and [CredentialRequestProof],
     * typically a URI.
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
    /**
     * Set this variable to use JAR (JWT-secured authorization requests, RFC 9101)
     * for PAR (Pushed authorization requests, RFC 9126), as mandated by OpenID4VC HAIP.
     */
    val jwsService: JwsService? = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithSelfSignedCert())),
) {

    /**
     * Send the result as parameters to the server at [OAuth2AuthorizationServerMetadata.authorizationEndpoint].
     * Use POST if [OAuth2AuthorizationServerMetadata.pushedAuthorizationRequestEndpoint] is available.
     *
     * Wraps the actual authorization request in a pushed authorization request (i.e. the `request` property),
     * if the [jwsService] is available.
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
     * @param audience for PAR the value of the `issuer` of the Authorization Server
     */
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null,
        issuerState: String? = null,
        audience: String? = null,
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
    ).wrapIfNecessary(audience)

    private suspend fun AuthenticationRequestParameters.wrapIfNecessary(audience: String?) =
        if (jwsService != null) wrapInPar(jwsService, audience) else this

    private suspend fun AuthenticationRequestParameters.wrapInPar(
        jwsService: JwsService,
        audience: String?,
    ) = AuthenticationRequestParameters(
        clientId = clientId,
        request = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = jwsService.algorithm,
                type = JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST
            ),
            payload = this.copy(
                audience = audience,
                issuer = this.clientId,
            ),
            serializer = AuthenticationRequestParameters.serializer(),
            addJsonWebKey = true,
        ).getOrThrow().serialize()
    )

    /**
     * Send the result as parameters to the server at [OAuth2AuthorizationServerMetadata.authorizationEndpoint].
     * Use this method if the previous authn request was sent as a pushed authorization request (RFC 9126),
     * and the server has answered with [PushedAuthenticationResponseParameters].
     *
     * @param parResponse response from the AS to the PAR request
     */
    suspend fun createAuthRequestAfterPar(
        parResponse: PushedAuthenticationResponseParameters,
    ) = AuthenticationRequestParameters(
        clientId = clientId,
        requestUri = parResponse.requestUri,
    )

    @OptIn(ExperimentalStdlibApi::class)
    suspend fun generateCodeVerifier(state: String): String {
        val codeVerifier = Random.nextBytes(32).toHexString(HexFormat.Default)
        stateToCodeStore.put(state, codeVerifier)
        return codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
    }

    sealed class AuthorizationForToken {
        /**
         * Authorization code from an actual OAuth2 Authorization Server, or [SimpleAuthorizationService.authorize]
         */
        data class Code(val code: String) : AuthorizationForToken()

        /**
         * Pre-auth code from [CredentialOfferGrantsPreAuthCode.preAuthorizedCode] in
         * [CredentialOfferGrants.preAuthorizedCode] in [CredentialOffer.grants],
         * optionally with a [transactionCode] which is transmitted out-of-band, and may be entered by the user.
         */
        data class PreAuthCode(
            val preAuthorizedCode: String,
            val transactionCode: String? = null,
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
     * see [buildDPoPHeader].
     *
     * @param state to keep internal state in further requests
     * @param authorization for the token endpoint
     * @param authorizationDetails from RFC 9396 OAuth 2.0 Rich Authorization Requests
     * @param scope in OID4VCI flows the value `scope` from [IssuerMetadata.supportedCredentialConfigurations]
     * @param resource from RFC 8707 Resource Indicators for OAuth 2.0, in OID4VCI flows the value
     * of [IssuerMetadata.credentialIssuer]
     */
    suspend fun createTokenRequestParameters(
        state: String,
        authorization: AuthorizationForToken,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            codeVerifier = stateToCodeStore.remove(state),
            authorizationDetails = authorizationDetails,
            scope = scope,
            resource = resource,
            code = authorization.code,
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            codeVerifier = stateToCodeStore.remove(state),
            authorizationDetails = authorizationDetails,
            scope = scope,
            resource = resource,
            transactionCode = authorization.transactionCode,
            preAuthorizedCode = authorization.preAuthorizedCode,
        )
    }

}
