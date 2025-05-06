package at.asitplus.wallet.lib.agent.validation

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

fun interface TokenStatusResolver {
    suspend operator fun invoke(status: Status): KmmResult<TokenStatus>
}