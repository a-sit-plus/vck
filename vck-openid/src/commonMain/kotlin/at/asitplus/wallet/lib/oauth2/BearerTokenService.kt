package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

/**
 * Combines simple bearer tokens from [BearerTokenGenerationService] and [BearerTokenVerificationService].
 */
class BearerTokenService(
    override val generation: BearerTokenGenerationService,
    override val verification: BearerTokenVerificationService,
    override val dpopSigningAlgValuesSupportedStrings: Set<String>?,
    override val supportsRefreshTokens: Boolean,
) : TokenService {

    @Suppress("OVERRIDE_DEPRECATION")
    override suspend fun readUserInfo(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken =
        if (authorizationHeader.startsWith(OpenIdConstants.TOKEN_TYPE_BEARER, ignoreCase = true)) {
            val token = authorizationHeader.removePrefix(OpenIdConstants.TOKEN_PREFIX_BEARER).split(" ").last()
            generation.verifyAccessToken(token)
                ?: throw OAuth2Exception.InvalidToken("access token not valid: $token")
        } else {
            throw OAuth2Exception.InvalidToken("authorization header not valid: $authorizationHeader")
        }

    @Suppress("OVERRIDE_DEPRECATION")
    override suspend fun validateTokenForTokenExchange(
        subjectToken: String,
        httpRequest: RequestInfo?,
    ): KmmResult<ValidatedAccessToken> =
        validateAccessToken(subjectToken, httpRequest, null)

}