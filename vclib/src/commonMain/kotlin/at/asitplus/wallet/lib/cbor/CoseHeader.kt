package at.asitplus.wallet.lib.cbor

import at.asitplus.wallet.lib.iso.cborSerializer
import io.github.aakira.napier.Napier
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Protected header of a [CoseSigned].
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseHeader(
    @SerialLabel(1)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,
    @SerialLabel(2)
    @SerialName("crit")
    val criticalHeaders: String? = null,
    @SerialLabel(3)
    @SerialName("content type")
    val contentType: String? = null,
    @SerialLabel(4)
    @SerialName("kid")
    val kid: String? = null,
    @SerialLabel(5)
    @SerialName("IV")
    @ByteString
    val iv: ByteArray? = null,
    @SerialLabel(6)
    @SerialName("Partial IV")
    @ByteString
    val partialIv: ByteArray? = null,
) {

    fun serialize() = cborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseHeader

        if (algorithm != other.algorithm) return false
        if (criticalHeaders != other.criticalHeaders) return false
        if (contentType != other.contentType) return false
        if (kid != other.kid) return false
        if (iv != null) {
            if (other.iv == null) return false
            if (!iv.contentEquals(other.iv)) return false
        } else if (other.iv != null) return false
        if (partialIv != null) {
            if (other.partialIv == null) return false
            if (!partialIv.contentEquals(other.partialIv)) return false
        } else if (other.partialIv != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + (criticalHeaders?.hashCode() ?: 0)
        result = 31 * result + (contentType?.hashCode() ?: 0)
        result = 31 * result + (kid?.hashCode() ?: 0)
        result = 31 * result + (iv?.contentHashCode() ?: 0)
        result = 31 * result + (partialIv?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}