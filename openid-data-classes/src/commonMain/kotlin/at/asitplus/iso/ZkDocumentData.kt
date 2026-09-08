package at.asitplus.iso

import kotlinx.serialization.Contextual
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ValueTags
import kotlin.time.Instant

/**
 * Part of the ISO/IEC 18013-5:2026 standard: ZKP Mdoc response (10.3.4)
 */
@Serializable
data class ZkDocumentData (
    @SerialName(PROP_DOC_TYPE)
    val docType: String,
    @SerialName(PROP_ZK_SYSTEM_ID)
    val zkSystemId: String,
    @SerialName(PROP_TIME_STAMP)
    @ValueTags(0u)
    val timestamp: Instant,
    @SerialName(PROP_ZK_ISSUER_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val issuerSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_ZK_DEVICE_SIGNED)
    @Serializable(with = NamespacedZkSignedListSerializer::class)
    val deviceSigned: Map<String, @Contextual ZkSignedList>? = null,
    @SerialName(PROP_CERT_CHAIN)
    @Serializable(with = NormalizedX509Serializer::class)
    val certificateChain: List<ByteArray>? = null,
) {
    init {
        require(certificateChain == null || certificateChain.isNotEmpty()) {
            "Certificate chain must be null or contain at least one certificate."
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ZkDocumentData) return false

        if (docType != other.docType) return false
        if (zkSystemId != other.zkSystemId) return false
        if (timestamp != other.timestamp) return false
        if (issuerSigned != other.issuerSigned) return false
        if (deviceSigned != other.deviceSigned) return false

        if (certificateChain == null && other.certificateChain != null) return false
        if (certificateChain != null && other.certificateChain == null) return false
        if (certificateChain != null && other.certificateChain != null) {
            if (certificateChain.size != other.certificateChain.size) return false
            for (i in certificateChain.indices) {
                if (!certificateChain[i].contentEquals(other.certificateChain[i])) return false
            }
        }

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + zkSystemId.hashCode()
        result = 31 * result + timestamp.hashCode()
        result = 31 * result + issuerSigned.hashCode()
        result = 31 * result + deviceSigned.hashCode()
        result = 31 * result + (certificateChain?.sumOf { it.contentHashCode() } ?: 0)
        return result
    }

    companion object {
        internal const val PROP_CERT_CHAIN = "msoX5chain"
        internal const val PROP_DOC_TYPE = "docType"
        internal const val PROP_ZK_SYSTEM_ID = "zkSystemId"
        internal const val PROP_TIME_STAMP = "timestamp"
        internal const val PROP_ZK_ISSUER_SIGNED = "issuerSigned"
        internal const val PROP_ZK_DEVICE_SIGNED = "deviceSigned"

    }
}
