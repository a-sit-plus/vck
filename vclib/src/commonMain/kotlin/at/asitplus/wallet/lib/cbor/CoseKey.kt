package at.asitplus.wallet.lib.cbor

import at.asitplus.wallet.lib.iso.cborSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.component.base64.encodeBase64
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalSerializationApi::class)
@Serializable
data class CoseKey(
    @SerialLabel(1)
    @SerialName("kty")
    val type: CoseKeyType,
    @SerialLabel(2)
    @SerialName("kid")
    @ByteString
    val keyId: ByteArray? = null,
    @SerialLabel(3)
    @SerialName("alg")
    val algorithm: CoseAlgorithm? = null,
    @SerialLabel(4)
    @SerialName("key_ops")
    val operations: Array<CoseKeyOperation>? = null,
    @SerialLabel(5)
    @SerialName("Base IV")
    @ByteString
    val baseIv: ByteArray? = null,
    @SerialLabel(-1)
    @SerialName("crv")
    val curve: CoseEllipticCurve? = null,
    @SerialLabel(-2)
    @SerialName("x")
    val x: ByteArray? = null,
    @SerialLabel(-3)
    @SerialName("y") // TODO might also be bool
    val y: ByteArray? = null,
    @SerialLabel(-4)
    @SerialName("d")
    val d: ByteArray? = null,
) {
    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {

        fun deserialize(it: ByteArray) = kotlin.runCatching {
            cborSerializer.decodeFromByteArray<CoseHeader>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseKey

        if (type != other.type) return false
        if (keyId != null) {
            if (other.keyId == null) return false
            if (!keyId.contentEquals(other.keyId)) return false
        } else if (other.keyId != null) return false
        if (algorithm != other.algorithm) return false
        if (operations != null) {
            if (other.operations == null) return false
            if (!operations.contentEquals(other.operations)) return false
        } else if (other.operations != null) return false
        if (baseIv != null) {
            if (other.baseIv == null) return false
            if (!baseIv.contentEquals(other.baseIv)) return false
        } else if (other.baseIv != null) return false
        if (curve != other.curve) return false
        if (x != null) {
            if (other.x == null) return false
            if (!x.contentEquals(other.x)) return false
        } else if (other.x != null) return false
        if (y != null) {
            if (other.y == null) return false
            if (!y.contentEquals(other.y)) return false
        } else if (other.y != null) return false
        if (d != null) {
            if (other.d == null) return false
            if (!d.contentEquals(other.d)) return false
        } else if (other.d != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (operations?.contentHashCode() ?: 0)
        result = 31 * result + (baseIv?.contentHashCode() ?: 0)
        result = 31 * result + (curve?.hashCode() ?: 0)
        result = 31 * result + (x?.contentHashCode() ?: 0)
        result = 31 * result + (y?.contentHashCode() ?: 0)
        result = 31 * result + (d?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "CoseKey(type=$type, keyId=${keyId?.encodeBase64()}, algorithm=$algorithm, operations=${operations?.contentToString()}, baseIv=${baseIv?.encodeBase64()}, curve=$curve, x=${x?.encodeBase64()}, y=${y?.encodeBase64()}, d=${d?.encodeBase64()})"
    }


}
