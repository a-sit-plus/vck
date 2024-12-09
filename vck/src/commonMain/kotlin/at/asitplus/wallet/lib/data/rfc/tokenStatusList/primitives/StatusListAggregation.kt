package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class StatusListAggregation(
    @SerialName("status_lists")
    val statusLists: List<UniformResourceIdentifier>,
)