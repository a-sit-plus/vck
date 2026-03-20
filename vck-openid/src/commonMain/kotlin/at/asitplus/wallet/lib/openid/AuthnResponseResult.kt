package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult

/**
 * Result of validating an OpenID authentication response, covering success and error cases.
 * Use to inspect how a wallet response was parsed and whether presentation validation succeeded.
 */
data class AuthnResponseResult(
    val idToken: KmmResult<at.asitplus.openid.IdToken>?,
    val vpTokenValidationResult: KmmResult<VpTokenValidationResult>?,
    val state: String?,
)
