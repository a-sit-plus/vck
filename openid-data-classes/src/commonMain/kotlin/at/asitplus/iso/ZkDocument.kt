package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.ValueTags

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for mdoc request in ZK (10.3.4)
 */
@Serializable
data class ZkDocument (
    @SerialName("zkDocumentDataBytes")
    @ValueTags(24U)
    val zkDocumentDataBytes: ByteStringWrapper<ZkDocumentData>,
    @SerialName("proof")
    @ByteString
    val proof: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ZkDocument

        if (zkDocumentDataBytes != other.zkDocumentDataBytes) return false
        if (!proof.contentEquals(other.proof)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = zkDocumentDataBytes.hashCode()
        result = 31 * result + proof.contentHashCode()
        return result
    }
}
