package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

/**
 * An Issuer issues Referenced Tokens to a Holder, the Holder uses and presents those Referenced
 * Tokens to a Relying Party. The Issuer gives updated status information to the Status Issuer
 */
interface ReferencedTokenIssuer<TokenRequest: Any, Token: Any> {
    suspend fun issueToken(tokenRequest: TokenRequest): Token
}
