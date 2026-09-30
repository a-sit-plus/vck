package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus

internal interface JavaReferencedTokenStore : ReferencedTokenStore {
    fun setStatus(timePeriod: Int, index: Long, status: Int): Boolean

    override fun setStatus(timePeriod: Int, index: ULong, status: TokenStatus): Boolean =
        setStatus(
            timePeriod = timePeriod,
            index = index.toLong().also {
                require(index <= Long.MAX_VALUE.toULong()) { "index must not exceed ${Long.MAX_VALUE}" }
            },
            status = status.value.toInt(),
        )
}
