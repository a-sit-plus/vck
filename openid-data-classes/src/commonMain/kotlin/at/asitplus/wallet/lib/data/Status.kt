package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo.StatusSurrogateSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Legacy status claim wrapper kept for binary/source compatibility. Only used for correct serialization structure.
 *
 * Please use [RevocationListInfo] with [StatusSurrogateSerializer]
 * which enforces the single-choice constraint and aligns with JOSE/COSE field names.
 */
@Deprecated(
    message = "Use RevocationListInfo directly with StatusSurrogateSerializer instead",
)
@Serializable
data class Status(
    @SerialName("status_list")
    val statusList: StatusListInfo? = null,

    @SerialName("identifier_list")
    val identifierList: IdentifierListInfo? = null,
)
