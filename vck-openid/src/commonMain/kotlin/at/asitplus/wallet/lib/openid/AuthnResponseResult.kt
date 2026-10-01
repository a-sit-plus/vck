package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.IdToken

/**
 * Result of validating an OpenID authentication response.
 * Use to inspect how a wallet response was parsed and whether presentation validation succeeded.
 */
data class AuthnResponseResult(
    @Deprecated("Support for SIOPv2 has been removed")
    val idTokenValidationResult: KmmResult<IdToken>?,
    val vpTokenValidationResult: KmmResult<VpTokenValidationResult>?,
    val request: AuthenticationRequestParameters?,
) : DcApiResponseResult {
    val state
        get() = request?.state
}