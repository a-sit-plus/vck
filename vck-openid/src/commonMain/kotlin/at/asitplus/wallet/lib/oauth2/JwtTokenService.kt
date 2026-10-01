package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken

/**
 * Combines sender-constrained JWT tokens from [JwtTokenGenerationService] and [JwtTokenVerificationService].
 */
class JwtTokenService(
    override val generation: JwtTokenGenerationService,
    override val verification: JwtTokenVerificationService,
    override val dpopSigningAlgValuesSupportedStrings: Set<String>?,
    override val supportsRefreshTokens: Boolean,
) : TokenService {

    /** Tokens are DPoP bound, and [validateAccessToken] rejects a subject token bound to another key. */
    override val supportsTokenExchange: Boolean = true

    /**
     * Validates the access token, and — since [generation] issued it — resolves the user info stored back then,
     * so callers do not need a second lookup with [readUserInfo].
     */
    override suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
        validatedClientKey: JsonWebKey?,
    ): KmmResult<ValidatedAccessToken> = catching {
        val validated = verification.validateAccessToken(
            tokenOrAuthHeader = authorizationHeader,
            httpRequest = httpRequest,
            validatedClientKey = validatedClientKey
        ).getOrThrow()
        validated.jwtId
            ?.let { generation.getUserInfoExtended(it) }
            ?.let { validated.copy(userInfoExtended = it) }
            ?: validated
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override suspend fun readUserInfo(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken = if (authorizationHeader.startsWith(OpenIdConstants.TOKEN_TYPE_DPOP, ignoreCase = true)) {
        val accessToken = authorizationHeader.removePrefix(OpenIdConstants.TOKEN_PREFIX_DPOP).split(" ").last()
        // Verifies signature, typ, jti, nbf and exp; does not prove possession of the key the token is bound to
        val tokenJwt = verification.validateToken(accessToken, JwsContentTypeConstants.OID4VCI_AT_JWT)
        val jwtId = tokenJwt.payload.jwtId
            ?: throw InvalidToken("access token not valid: $accessToken")
        with(tokenJwt.payload) {
            toValidatedAccessToken(accessToken, generation.getUserInfoExtended(jwtId))
        }
    } else {
        throw InvalidToken("authorization header not valid: $authorizationHeader")
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override suspend fun validateTokenForTokenExchange(
        subjectToken: String,
        httpRequest: RequestInfo?,
    ): KmmResult<ValidatedAccessToken> =
        validateAccessToken(subjectToken, httpRequest, null)

}
