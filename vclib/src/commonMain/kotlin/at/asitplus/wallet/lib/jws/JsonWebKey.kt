package at.asitplus.wallet.lib.jws

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.CryptoPublicKey
import at.asitplus.wallet.lib.data.Base64Strict
import at.asitplus.wallet.lib.data.jsonSerializer
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okio.ByteString.Companion.toByteString

@Serializable
data class JsonWebKey(
    @SerialName("crv")
    val curve: EcCurve? = null,
    @SerialName("kty")
    val type: JwkType? = null,
    @SerialName("kid")
    val keyId: String? = null,
    @SerialName("x")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val x: ByteArray? = null,
    @SerialName("y")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val y: ByteArray? = null,
    @SerialName("n")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val n: ByteArray? = null,
    @SerialName("e")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val e: ByteArray? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {

        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JsonWebKey>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

        fun fromKeyId(it: String): JsonWebKey? {
            // TODO RSA
            val (xCoordinate, yCoordinate) = MultibaseHelper.calcPublicKey(it)
                ?: return null
            return JsonWebKey(
                type = JwkType.EC,
                curve = EcCurve.SECP_256_R_1,
                keyId = it,
                x = xCoordinate,
                y = yCoordinate
            )
        }

        fun fromAnsiX963Bytes(type: JwkType, curve: EcCurve, it: ByteArray): JsonWebKey? {
            // TODO RSA
            if (type != JwkType.EC || curve != EcCurve.SECP_256_R_1) {
                return null
            }
            if (it.size != 1 + 32 + 32 || it[0] != 0x04.toByte()) {
                return null
            }
            val xCoordinate = it.sliceArray(1 until 33)
            val yCoordinate = it.sliceArray(33 until 65)
            val keyId = MultibaseHelper.calcKeyId(curve, xCoordinate, yCoordinate)
                ?: return null
            return JsonWebKey(
                type = type,
                curve = curve,
                keyId = keyId,
                x = xCoordinate,
                y = yCoordinate
            )
        }

        fun fromCoordinates(
            type: JwkType,
            curve: EcCurve,
            x: ByteArray,
            y: ByteArray
        ): JsonWebKey? {
            // TODO RSA
            if (type != JwkType.EC || curve != EcCurve.SECP_256_R_1) {
                return null
            }
            val keyId = MultibaseHelper.calcKeyId(curve, x, y)
                ?: return null
            return JsonWebKey(
                type = type,
                curve = curve,
                keyId = keyId,
                x = x,
                y = y
            )
        }
    }

    fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
        if (x != null && y != null)
            return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
        return KmmResult.failure(IllegalArgumentException())
    }

    val jwkThumbprint: String by lazy {
        Json.encodeToString(this).encodeToByteArray().toByteString().sha256().base64Url()
    }

    val identifier: String by lazy {
        keyId ?: "urn:ietf:params:oauth:jwk-thumbprint:sha256:${jwkThumbprint}"
    }

    override fun toString(): String {
        return "JsonWebKey(type=$type, curve=$curve, keyId=$keyId," +
                " x=${x?.encodeToString(Base64Strict)}," +
                " y=${y?.encodeToString(Base64Strict)})"
    }

    fun toCryptoPublicKey(): CryptoPublicKey? {
        return when (this.type) {
            JwkType.EC -> {
                if (this.curve == null || this.x == null || this.y == null) return null
                CryptoPublicKey.Ec(
                    curve = this.curve,
                    keyId = identifier,
                    x = x,
                    y = y,
                )
            }

            JwkType.RSA -> {
                if (this.n == null || this.e == null) return null
                CryptoPublicKey.Rsa(
                    keyId = identifier,
                    n = n,
                    e = e
                )
            }

            null -> null
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JsonWebKey

        if (curve != other.curve) return false
        if (type != other.type) return false
        if (keyId != other.keyId) return false
        if (x != null) {
            if (other.x == null) return false
            if (!x.contentEquals(other.x)) return false
        } else if (other.x != null) return false
        if (y != null) {
            if (other.y == null) return false
            if (!y.contentEquals(other.y)) return false
        } else if (other.y != null) return false
        if (n != null) {
            if (other.n == null) return false
            if (!n.contentEquals(other.n)) return false
        } else if (other.n != null) return false
        if (e != null) {
            if (other.e == null) return false
            if (!e.contentEquals(other.e)) return false
        } else if (other.e != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = curve?.hashCode() ?: 0
        result = 31 * result + (type?.hashCode() ?: 0)
        result = 31 * result + (keyId?.hashCode() ?: 0)
        result = 31 * result + (x?.contentHashCode() ?: 0)
        result = 31 * result + (y?.contentHashCode() ?: 0)
        result = 31 * result + (n?.contentHashCode() ?: 0)
        result = 31 * result + (e?.contentHashCode() ?: 0)
        return result
    }


}
