package at.asitplus.wallet.lib.agent.validation

import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier

fun interface StatusListTokenResolver {
    suspend operator fun invoke(statusListUrl: UniformResourceIdentifier): StatusListToken
}