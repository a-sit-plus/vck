package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import kotlin.random.Random
import kotlin.time.Clock

/** Drops bytes at the start, or adds zero bytes at the start, until the [size] is reached */
fun ByteArray.ensureSize(size: Int): ByteArray = (this.size - size).let { toDrop ->
    when {
        toDrop > 0 -> this.copyOfRange(toDrop, this.size)
        toDrop < 0 -> ByteArray(-toDrop) + this
        else -> this
    }
}


fun randomCwtOrJwtResolver(statusListIssuer: StatusListAgent) = TokenStatusResolverImpl(
    resolveStatusListToken = {
        if (Random.nextBoolean()) StatusListJwt(
            statusListIssuer.issueStatusListJwt(),
            resolvedAt = Clock.System.now(),
        ) else StatusListCwt(
            statusListIssuer.issueStatusListCwt(),
            resolvedAt = Clock.System.now(),
        )
    },
)
