package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception

/**
 * Combines sender-constrained JWT tokens from [JwtTokenGenerationService] and [JwtTokenVerificationService].
 */
class JwtTokenService(
    override val generation: JwtTokenGenerationService,
    override val verification: JwtTokenVerificationService,
    override val dpopSigningAlgValuesSupportedStrings: Set<String>?,
    override val supportsRefreshTokens: Boolean,
) : TokenService {

    /**
     * Validates that the token sent from the client is actually one issued from [generation],
     * and that the client presented a valid proof-of-possession for the key the token is bound to.
     */
    override suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken = if (authorizationHeader.startsWith(OpenIdConstants.TOKEN_TYPE_DPOP, ignoreCase = true)) {
        val dpopToken = authorizationHeader.removePrefix(OpenIdConstants.TOKEN_PREFIX_DPOP).split(" ").last()
        val dpopTokenJwt = verification.validateDpopToken(dpopToken, JwsContentTypeConstants.OID4VCI_AT_JWT)
        val jwtId = dpopTokenJwt.payload.jwtId
            ?: throw OAuth2Exception.InvalidToken("access token not valid: $dpopToken")
        verification.validateDpopJwt(dpopToken, dpopTokenJwt, request)
        with(dpopTokenJwt.payload) {
            toValidatedAccessToken(dpopToken, jwtId)
        }
    } else {
        throw OAuth2Exception.InvalidToken("authorization header not valid: $authorizationHeader")
    }

    /**
     * Validates the subject token (that is a token sent by a third party) for token exchange) is one issued from
     * [generation], and that the client presented a valid proof-of-possession for the key the token is bound to.
     * Callers need to authenticate the client before calling this method.
     */
    override suspend fun validateTokenForTokenExchange(
        subjectToken: String,
    ): ValidatedAccessToken = run {
        val dpopTokenJwt = verification.validateDpopToken(subjectToken, JwsContentTypeConstants.OID4VCI_AT_JWT)
        val jwtId = dpopTokenJwt.payload.jwtId
            ?: throw OAuth2Exception.InvalidToken("access token not valid: $subjectToken")
        // can't validate DPoP JWT, as the third party can't forward this
        with(dpopTokenJwt.payload) {
            toValidatedAccessToken(subjectToken, jwtId)
        }
    }

    private suspend fun OpenId4VciAccessToken.toValidatedAccessToken(
        dpopToken: String,
        jwtId: String,
    ): ValidatedAccessToken = ValidatedAccessToken(
        token = dpopToken,
        userInfoExtended = generation.getUserInfoExtended(jwtId),
        authorizationDetails = authorizationDetails?.filterIsInstance<OpenIdAuthorizationDetails>()?.toSet(),
        scope = scope
    )
}