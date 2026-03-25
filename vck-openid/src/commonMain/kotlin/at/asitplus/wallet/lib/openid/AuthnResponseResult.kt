package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters

/**
 * Result of validating an OpenID authentication response.
 * Use to inspect how a wallet response was parsed and whether presentation validation succeeded.
 */
data class AuthnResponseResult(
    val idTokenValidationResult: KmmResult<at.asitplus.openid.IdToken>?,
    val vpTokenValidationResult: KmmResult<VpTokenValidationResult>?,
    val request: AuthenticationRequestParameters?,
) {
    val state
        get() = request?.state
}