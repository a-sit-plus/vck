package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidDpopProof
import kotlin.time.Clock
import kotlin.time.Clock.System
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/** Strategy to generate access tokens, to use in [SimpleAuthorizationService]. */
interface TokenGenerationService {
    /** Builds an access token, probably with a refresh token. Input parameters are assumed to be validated already. */
    suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
        validatedClientKey: JsonWebKey?,
    ): TokenResponseParameters

    suspend fun dpopNonce(): String?
}

/**
 * Simple DPoP token generation for an OAuth 2.0 authorization server, with [OpenId4VciAccessToken] as payload.
 *
 * Implemented from
 * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 */
class JwtTokenGenerationService(
    /** Used to create nonces for tokens during issuing. */
    internal val nonceService: NonceService,
    /** Used to create nonces for refresh tokens during issuing, which are long-lived. */
    internal val refreshTokenNonceService: NonceService,
    /** Used to create nonces for DPoP proofs of clients. */
    internal val dpopNonceService: NonceService,
    /** Used as issuer for issued DPoP tokens. */
    internal val publicContext: String = "https://wallet.a-sit.at/authorization-server",
    /** Key material used to sign the DPoP tokens in [signToken]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Used to sign DPoP (RFC 9449) access tokens, if supported by the client. */
    internal val signToken: SignJwtFun<OpenId4VciAccessToken> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    /** Clock used to verify timestamps in access tokens and refresh tokens. */
    private val clock: Clock = System,
    /** Whether to issue refresh tokens, which may be used by clients to get a new access token. */
    private val issueRefreshToken: Boolean = false,
    /** Maps the issued token's `jwtId` to the user info. */
    private val jwtIdToUserInfoExtended: MapStore<String, OidcUserInfoExtended> = DefaultMapStore(),
    /** Maps the issued refresh token's `jwtId` (long-lived!) to the user info. */
    private val refreshTokenJwtIdToUserInfoExtended: MapStore<String, OidcUserInfoExtended> =
        DefaultMapStore(lifetime = 30.days),
) : TokenGenerationService {

    override suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
        validatedClientKey: JsonWebKey?,
    ): TokenResponseParameters = if (httpRequest?.dpop == null) {
        throw InvalidDpopProof("no dpop proof in header")
    } else {
        val notBefore = clock.now().truncateToSeconds()
        TokenResponseParameters(
            expires = 5.minutes,
            tokenType = TOKEN_TYPE_DPOP,
            refreshToken = if (issueRefreshToken) signToken(
                JwsContentTypeConstants.RT_JWT,
                OpenId4VciAccessToken(
                    issuer = publicContext,
                    jwtId = refreshTokenNonceService.provideNonce().also {
                        refreshTokenJwtIdToUserInfoExtended.put(it, userInfo)
                    },
                    notBefore = notBefore,
                    expiration = notBefore.plus(30.days),
                    confirmationClaim = validatedClientKey?.let {
                        ConfirmationClaim(
                            jsonWebKeyThumbprint = it.jwkThumbprintPlain
                        )
                    },
                    scope = scope,
                    authorizationDetails = authorizationDetails,
                ),
                OpenId4VciAccessToken.serializer(),
            ).getOrThrow().serialize() else null,
            accessToken = signToken(
                JwsContentTypeConstants.OID4VCI_AT_JWT,
                OpenId4VciAccessToken(
                    issuer = publicContext,
                    jwtId = nonceService.provideNonce().also {
                        jwtIdToUserInfoExtended.put(it, userInfo)
                    },
                    notBefore = notBefore,
                    expiration = notBefore.plus(5.minutes),
                    confirmationClaim = validatedClientKey?.let {
                        ConfirmationClaim(
                            jsonWebKeyThumbprint = it.jwkThumbprintPlain
                        )
                    },
                    scope = scope,
                    authorizationDetails = authorizationDetails,
                ),
                OpenId4VciAccessToken.serializer(),
            ).getOrThrow().serialize(),
            authorizationDetails = authorizationDetails,
            scope = scope,
        )
    }


    private val JsonWebKey.jwkThumbprintPlain
        get() = this.jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")

    suspend fun getUserInfoExtended(jwtId: String) =
        jwtIdToUserInfoExtended.remove(jwtId) ?: refreshTokenJwtIdToUserInfoExtended.remove(jwtId)

    override suspend fun dpopNonce() = dpopNonceService.provideNonce()
}

/**
 * Simple bearer token generation (just a nonce) for an OAuth 2.0 authorization server.
 */
class BearerTokenGenerationService(
    /** Used to create nonces for tokens during issuing. */
    internal val nonceService: NonceService = DefaultNonceService(),
    private val accessTokenToValidatedAccessToken: MapStore<String, ValidatedAccessToken> = DefaultMapStore(),
) : TokenGenerationService {

    override suspend fun buildToken(
        httpRequest: RequestInfo?,
        userInfo: OidcUserInfoExtended,
        authorizationDetails: Set<AuthorizationDetails>?,
        scope: String?,
        validatedClientKey: JsonWebKey?
    ): TokenResponseParameters = TokenResponseParameters(
        expires = 5.minutes,
        tokenType = TOKEN_TYPE_BEARER,
        accessToken = nonceService.provideNonce(),
        authorizationDetails = authorizationDetails,
        scope = scope,
    ).also {
        accessTokenToValidatedAccessToken.put(
            it.accessToken,
            ValidatedAccessToken(
                token = it.accessToken,
                userInfoExtended = userInfo,
                authorizationDetails = authorizationDetails,
                scope = scope
            )
        )
    }

    suspend fun removeAccessToken(accessToken: String) =
        accessTokenToValidatedAccessToken.remove(accessToken)

    suspend fun verifyAccessToken(accessToken: String) =
        accessTokenToValidatedAccessToken.get(accessToken)

    override suspend fun dpopNonce() = null
}
