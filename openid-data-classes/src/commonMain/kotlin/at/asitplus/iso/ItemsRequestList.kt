package at.asitplus.iso

import kotlinx.serialization.Serializable

/**
 * Convenience class with a custom serializer ([at.asitplus.wallet.lib.iso.ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 */
@Serializable(with = ItemsRequestListSerializer::class)
data class ItemsRequestList(
    val entries: List<SingleItemsRequest>
)