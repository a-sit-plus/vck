package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.wallet.lib.oidvci.TokenInfo
import kotlinx.serialization.Serializable

/** Internal class representing issued tokens and tokens presented by clients that have been verified successfully. */
@Serializable
data class ValidatedAccessToken(
    /** The token value as it has been sent verbatim to the client. */
    val token: String,
    /** User information associated with this token. */
    val userInfoExtended: OidcUserInfoExtended? = null,
    /** See [at.asitplus.openid.TokenResponseParameters.authorizationDetails] */
    val authorizationDetails: Set<AuthorizationDetails>? = null,
    /** See [at.asitplus.openid.TokenResponseParameters.scope] */
    val scope: String? = null,
    /** `jti` of the access token, if it is a JWT, to look up the user info stored when it was issued. */
    val jwtId: String? = null,
) {
    fun toTokenInfo() = TokenInfo(
        token = token,
        authorizationDetails = authorizationDetails,
        scope = scope,
    )

    val validCredentialIdentifiers: Collection<String>
        get() = authorizationDetails
            ?.filterIsInstance<OpenIdAuthorizationDetails>()
            ?.flatMap { it.credentialIdentifiers ?: setOf() }
            ?: setOf()
}

internal fun OpenId4VciAccessToken.toValidatedAccessToken(
    accessToken: String,
    userInfo: OidcUserInfoExtended?,
): ValidatedAccessToken = ValidatedAccessToken(
    token = accessToken,
    userInfoExtended = userInfo,
    authorizationDetails = authorizationDetails?.filterIsInstance<OpenIdAuthorizationDetails>()?.toSet(),
    scope = scope,
    jwtId = jwtId,
)
