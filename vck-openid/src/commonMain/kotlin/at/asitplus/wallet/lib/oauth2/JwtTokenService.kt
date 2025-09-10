package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
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

    /**
     * Provides information about the access token from [authorizationHeader], if it has been issued by [generation].
     * **Access token needs to be validated before (see [TokenVerificationService.validateAccessToken])**
     */
    override suspend fun readUserInfo(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken = if (authorizationHeader.startsWith(OpenIdConstants.TOKEN_TYPE_DPOP, ignoreCase = true)) {
        val accessToken = authorizationHeader.removePrefix(OpenIdConstants.TOKEN_PREFIX_DPOP).split(" ").last()
        val tokenJwt = JwsSigned
            .deserialize<OpenId4VciAccessToken>(OpenId4VciAccessToken.serializer(), accessToken, vckJsonSerializer)
            .getOrElse { throw InvalidToken("could not parse DPoP Token", it) }
        val jwtId = tokenJwt.payload.jwtId
            ?: throw InvalidToken("access token not valid: $accessToken")
        with(tokenJwt.payload) {
            toValidatedAccessToken(accessToken, jwtId)
        }
    } else {
        throw InvalidToken("authorization header not valid: $authorizationHeader")
    }

    /**
     * Validates the subject token (that is a token sent by a third party) for token exchange) is one issued from
     * [generation], and that the client presented a valid proof-of-possession for the key the token is bound to.
     * Callers need to authenticate the client before calling this method.
     */
    override suspend fun validateTokenForTokenExchange(
        subjectToken: String,
    ): ValidatedAccessToken = run {
        val tokenJwt = verification.validateToken(subjectToken, JwsContentTypeConstants.OID4VCI_AT_JWT)
        val jwtId = tokenJwt.payload.jwtId
            ?: throw InvalidToken("access token not valid: $subjectToken")
        // can't validate DPoP JWT, as the third party can't forward this
        with(tokenJwt.payload) {
            toValidatedAccessToken(subjectToken, jwtId)
        }
    }

    private suspend fun OpenId4VciAccessToken.toValidatedAccessToken(
        accessToken: String,
        jwtId: String,
    ): ValidatedAccessToken = ValidatedAccessToken(
        token = accessToken,
        userInfoExtended = generation.getUserInfoExtended(jwtId),
        authorizationDetails = authorizationDetails?.filterIsInstance<OpenIdAuthorizationDetails>()?.toSet(),
        scope = scope
    )
}