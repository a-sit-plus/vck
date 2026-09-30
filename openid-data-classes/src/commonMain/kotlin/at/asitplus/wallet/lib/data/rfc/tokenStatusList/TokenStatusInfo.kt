package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Status information embedded in a referenced token.
 *
 * Every non-null property represents one status mechanism. A status structure may carry several
 * mechanisms at the same time, but it must not be empty.
 */
@Serializable
data class TokenStatusInfo(
    @SerialName("status_list")
    val statusList: StatusListInfo? = null,

    @SerialName("identifier_list")
    val identifierList: IdentifierListInfo? = null,
) {
    init {
        require(statusList != null || identifierList != null) {
            "At least one token status mechanism must be present"
        }
    }

    val mechanisms: List<RevocationListInfo>
        get() = listOfNotNull(statusList, identifierList)

    companion object {
        /** Wraps a single status mechanism in its wire-level status object. */
        fun from(status: RevocationListInfo): TokenStatusInfo = when (status) {
            is StatusListInfo -> TokenStatusInfo(
                statusList = status,
                identifierList = status.identifierListInfo,
            )
            is IdentifierListInfo -> TokenStatusInfo(identifierList = status)
        }
    }
}
