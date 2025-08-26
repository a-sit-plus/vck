package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

class BearerTokenService(
    override val generation: BearerTokenGenerationService,
    override val verification: BearerTokenVerificationService,
    override val dpopSigningAlgValuesSupportedStrings: Set<String>?,
    override val supportsRefreshTokens: Boolean,
) : TokenService {

    override suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken =
        if (authorizationHeader.startsWith(OpenIdConstants.TOKEN_TYPE_BEARER, ignoreCase = true)) {
            val token = authorizationHeader.removePrefix(OpenIdConstants.TOKEN_PREFIX_BEARER).split(" ").last()
            generation.verifyAccessToken(token) // When to remove them?
                ?: throw OAuth2Exception.InvalidToken("access token not valid: $token")
        } else {
            throw OAuth2Exception.InvalidToken("authorization header not valid: $authorizationHeader")
        }

    override suspend fun validateTokenForTokenExchange(
        subjectToken: String,
    ): ValidatedAccessToken = run {
        generation.verifyAccessToken(subjectToken)
            ?: throw OAuth2Exception.InvalidToken("access token not valid: $subjectToken")
    }

}