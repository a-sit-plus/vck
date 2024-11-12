package at.asitplus.wallet.lib.iso

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ValueTags

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request (8.3.2.1.2.1)
 */
@OptIn(ExperimentalUnsignedTypes::class)
@Serializable
data class DocRequest(
    @SerialName("itemsRequest")
    @ValueTags(24U)
    val itemsRequest: ByteStringWrapper<ItemsRequest>,
    @SerialName("readerAuth")
    val readerAuth: CoseSigned<ByteArray>? = null,
) {
    override fun toString(): String {
        return "DocRequest(itemsRequest=${itemsRequest.value}, readerAuth=$readerAuth)"
    }

}