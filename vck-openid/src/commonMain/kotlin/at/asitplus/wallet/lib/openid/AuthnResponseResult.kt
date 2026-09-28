package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters

/**
 * Result of validating an OpenID authentication response.
 * Use to inspect how a wallet response was parsed and whether presentation validation succeeded.
 */
data class AuthnResponseResult(
    val vpTokenValidationResult: KmmResult<VpTokenValidationResult>?,
    val request: AuthenticationRequestParameters?,
) : DcApiResponseResult {
    val state
        get() = request?.state
}