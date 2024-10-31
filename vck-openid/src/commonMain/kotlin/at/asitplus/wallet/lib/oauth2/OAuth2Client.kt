package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.*
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
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
    private val clientId: String = "https://wallet.a-sit.at/app",
    /**
     * Used to create [AuthenticationRequestParameters] and [TokenRequestParameters].
     */
    private val redirectUrl: String = "$clientId/callback",
    /**
     * Used to store the code, associated to the state, to first send [AuthenticationRequestParameters.codeChallenge],
     * and then [TokenRequestParameters.codeVerifier], see [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636).
     */
    private val stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
) {

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [OAuth2AuthorizationServerMetadata.authorizationEndpoint]).
     *
     * Sample ktor code:
     * ```
     * val authnRequest = client.createAuthRequest(...)
     * val authnResponse = httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * val authn = AuthenticationResponseParameters.deserialize(authnResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param state to keep internal state in further requests
     * @param scope in OID4VCI flows the value `scope` from [IssuerMetadata.supportedCredentialConfigurations]
     * @param authorizationDetails from RFC 9396 OAuth 2.0 Rich Authorization Requests
     * @param resource from RFC 8707 Resource Indicators for OAuth 2.0, in OID4VCI flows the value
     * of [IssuerMetadata.credentialIssuer]
     */
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>? = null,
        scope: String? = null,
        resource: String? = null
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        authorizationDetails = authorizationDetails,
        scope = scope,
        resource = resource,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256
    )

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun generateCodeVerifier(state: String): String {
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
            val transactionCode: String? = null
        ) : AuthorizationForToken()
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [OAuth2AuthorizationServerMetadata.tokenEndpoint]).
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
     * see [JwsService.buildDPoPHeader].
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