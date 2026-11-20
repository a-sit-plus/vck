package at.asitplus.iso

import kotlinx.serialization.Serializable

/**
 * Convenience class with a custom serializer ([ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 *
 * Fails without any entry, as a name space requests at least one data element
 * (`DataElements = {+ DataElementIdentifier => IntentToRetain}`, ISO/IEC DIS 18013-5:2026, 10.2.3).
 */
@Serializable(with = ItemsRequestListSerializer::class)
data class ItemsRequestList(
    val entries: List<SingleItemsRequest>
) {
    init {
        require(entries.isNotEmpty()) { "A requested name space requests at least one data element" }
    }
}
