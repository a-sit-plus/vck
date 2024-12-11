package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

/**
 * Convenience class with a custom serializer ([IssuerSignedListSerializer]) to prevent
 * usage of the type `Map<String, List<ByteStringWrapper<IssuerSignedItem>>>` in [IssuerSigned.namespaces].
 */
data class IssuerSignedList(
    val entries: List<ByteStringWrapper<IssuerSignedItem>>
) {
    override fun toString(): String {
        return "IssuerSignedList(entries=${entries.map { it.value }})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerSignedList

        return entries == other.entries
    }

    override fun hashCode(): Int {
        return 31 * entries.hashCode()
    }

    companion object {
        /**
         * Ensures the serialization of this structure in [Document.issuerSigned]:
         * ```
         * IssuerNameSpaces = { ; Returned data elements for each namespace
         *     + NameSpace => [ + IssuerSignedItemBytes ]
         * }
         * IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem)
         * ```
         *
         * See ISO/IEC 18013-5:2021, 8.3.2.1.2.2 Device retrieval mdoc response
         */
        fun fromIssuerSignedItems(items: List<IssuerSignedItem>, namespace: String) =
            IssuerSignedList(items.map { item ->
                ByteStringWrapper(item, item.serialize(namespace).wrapInCborTag(24))
            })
    }
}
