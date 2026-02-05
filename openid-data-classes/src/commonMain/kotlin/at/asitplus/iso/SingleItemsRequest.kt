package at.asitplus.iso

/**
 * Convenience class with a custom serializer ([ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 */
data class SingleItemsRequest(
    val dataElementIdentifier: String,
    val intentToRetain: Boolean,
)