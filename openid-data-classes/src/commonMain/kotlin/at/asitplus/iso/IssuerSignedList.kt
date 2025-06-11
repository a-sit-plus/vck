package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.encodeToByteArray

/**
 * Convenience class with a custom serializer ([IssuerSignedListSerializer]) to prevent
 * usage of the type `Map<String, List<ByteStringWrapper<IssuerSignedItem>>>` in [at.asitplus.wallet.lib.iso.IssuerSigned.namespaces].
 */
data class IssuerSignedList(
    val entries: List<ByteStringWrapper<IssuerSignedItem>>,
) {
    override fun toString(): String = "IssuerSignedList(entries=${entries.map { it.value }})"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IssuerSignedList

        return entries == other.entries
    }

    override fun hashCode(): Int = 31 * entries.hashCode()

    companion object {
        /**
         * Ensures the serialization of this structure in [at.asitplus.wallet.lib.iso.Document.issuerSigned]:
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
                ByteStringWrapper(
                    item,
                    coseCompliantSerializer.encodeToByteArray(item.serialize(namespace)).wrapInCborTag(24)
                )
            })

        private fun IssuerSignedItem.serialize(namespace: String): ByteArray =
            coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(namespace, elementIdentifier), this)
    }
}
