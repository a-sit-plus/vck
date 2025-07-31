package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OidcUserInfoExtended

/**
 * Interface used in [CredentialAuthorizationServiceStrategy] to actually load user data during the OAuth 2.0 flow,
 * after an authn request (see [AuthenticationRequestParameters]) has been validated.
 */
@Deprecated("Use OAuth2LoadUserFun instead")
fun interface OAuth2DataProvider {
    /** [request] has been validated successfully, and this step loads the actual user data, if there is any. */
    suspend fun loadUserInfo(request: AuthenticationRequestParameters, code: String): OidcUserInfoExtended?
}

@Suppress("DEPRECATION")
class FallbackAdapter(private val dataProvider: OAuth2DataProvider?) : OAuth2LoadUserFun {
    override suspend fun invoke(
        input: OAuth2LoadUserFunInput,
    ): KmmResult<OidcUserInfoExtended> = catching {
        dataProvider?.loadUserInfo(input.request, input.code)
            ?: throw NotImplementedError()
    }

}