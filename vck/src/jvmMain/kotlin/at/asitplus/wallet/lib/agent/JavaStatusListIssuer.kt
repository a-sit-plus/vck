package at.asitplus.wallet.lib.agent

internal interface JavaStatusListIssuer : StatusListIssuer {
    override fun revokeCredentialByIndexLong(timePeriod: Int, statusListIndex: Long): Boolean

    override fun revokeCredentialByIndex(timePeriod: Int, statusListIndex: ULong): Boolean =
        revokeCredentialByIndexLong(
            timePeriod = timePeriod,
            statusListIndex = statusListIndex.toLong().also {
                require(statusListIndex <= Long.MAX_VALUE.toULong()) {
                    "statusListIndex must not exceed ${Long.MAX_VALUE}"
                }
            },
        )
}
