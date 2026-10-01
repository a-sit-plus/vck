package at.asitplus.iso

/**
 * Convenience class with a custom serializer ([ItemsRequestListSerializer]) to prevent
 * usage of the type `Map<String, Map<String, Boolean>>` in [ItemsRequest.namespaces].
 */
data class SingleItemsRequest(
    val dataElementIdentifier: String,
    /**
     * For each requested data element, this variable indicates whether the mdoc verifier
     * intends to retain the received data element. The mdoc verifier shall not retain any data, including
     * digests and signatures, or derived data received from the mdoc, except for data elements for which the
     * IntentToRetain flag was set to true in the request. To retain is defined as “to store for a period longer
     * than necessary to conduct the transaction in realtime”.
     */
    val intentToRetain: Boolean,
)