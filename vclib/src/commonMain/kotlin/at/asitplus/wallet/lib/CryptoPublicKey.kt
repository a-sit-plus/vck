package at.asitplus.wallet.lib

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.cbor.CoseAlgorithm
import at.asitplus.wallet.lib.cbor.CoseEllipticCurve
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.CoseKeyType
import at.asitplus.wallet.lib.jws.EcCurve
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JwkType
import at.asitplus.wallet.lib.jws.MultibaseHelper


sealed class CryptoPublicKey {

    abstract fun toCoseKey(): CoseKey
    abstract fun toJsonWebKey(): JsonWebKey

    data class Rsa(
        val keyId: String,
        val n: ByteArray,
        val e: ByteArray,
    ) : CryptoPublicKey() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Rsa

            if (keyId != other.keyId) return false
            if (!n.contentEquals(other.n)) return false
            if (!e.contentEquals(other.e)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = keyId.hashCode()
            result = 31 * result + n.contentHashCode()
            result = 31 * result + e.contentHashCode()
            return result
        }

        companion object {

            fun fromKeyId(it: String): CryptoPublicKey? {
                // TODO RSA
                return null
            }

            fun fromAnsiX963Bytes(it: ByteArray): CryptoPublicKey? {
                // TODO RSA
                return null
            }

            fun fromModulus(n: ByteArray, e: ByteArray): CryptoPublicKey {
                // TODO RSA
                return CryptoPublicKey.Rsa(
                    keyId = "TODO",
                    n = n,
                    e = e
                )
            }
        }

        fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
            // TODO RSA
            return KmmResult.success(byteArrayOf())
        }

        override fun toCoseKey() = CoseKey(
            type = CoseKeyType.RSA,
            keyId = keyId.encodeToByteArray(),
            algorithm = CoseAlgorithm.ES256,
            x = n,
            y = e
            // TODO RSA
        )

        override fun toJsonWebKey() = JsonWebKey(
            type = JwkType.RSA,
            keyId = keyId,
            n = n,
            e = e,
        )
    }

    data class Ec(
        val curve: EcCurve,
        val keyId: String,
        val x: ByteArray,
        val y: ByteArray,
    ) : CryptoPublicKey() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as Ec

            if (curve != other.curve) return false
            if (keyId != other.keyId) return false
            if (!x.contentEquals(other.x)) return false
            if (!y.contentEquals(other.y)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = curve.hashCode()
            result = 31 * result + keyId.hashCode()
            result = 31 * result + x.contentHashCode()
            result = 31 * result + y.contentHashCode()
            return result
        }

        companion object {

            fun fromKeyId(it: String): CryptoPublicKey? {
                val (xCoordinate, yCoordinate) = MultibaseHelper.calcPublicKey(it)
                    ?: return null
                return CryptoPublicKey.Ec(
                    curve = EcCurve.SECP_256_R_1,
                    keyId = it,
                    x = xCoordinate,
                    y = yCoordinate
                )
            }

            fun fromAnsiX963Bytes(curve: EcCurve, it: ByteArray): CryptoPublicKey? {
                if (curve != EcCurve.SECP_256_R_1) {
                    return null
                }
                if (it.size != 1 + 32 + 32 || it[0] != 0x04.toByte()) {
                    return null
                }
                val xCoordinate = it.sliceArray(1 until 33)
                val yCoordinate = it.sliceArray(33 until 65)
                val keyId = MultibaseHelper.calcKeyId(curve, xCoordinate, yCoordinate)
                    ?: return null
                return CryptoPublicKey.Ec(
                    curve = curve,
                    keyId = keyId,
                    x = xCoordinate,
                    y = yCoordinate
                )
            }

            fun fromCoordinates(curve: EcCurve, x: ByteArray, y: ByteArray): CryptoPublicKey? {
                if (curve != EcCurve.SECP_256_R_1) {
                    return null
                }
                val keyId = MultibaseHelper.calcKeyId(curve, x, y)
                    ?: return null
                return CryptoPublicKey.Ec(
                    curve = curve,
                    keyId = keyId,
                    x = x,
                    y = y
                )
            }
        }

        fun toAnsiX963ByteArray(): KmmResult<ByteArray> {
            return KmmResult.success(byteArrayOf(0x04.toByte()) + x + y);
        }

        override fun toCoseKey() = CoseKey(
            type = CoseKeyType.EC2,
            curve = curve.toCoseCurve(),
            keyId = keyId.encodeToByteArray(),
            algorithm = CoseAlgorithm.ES256,
            x = x,
            y = y
        )

        override fun toJsonWebKey() = JsonWebKey(
            curve = curve,
            type = JwkType.EC,
            keyId = keyId,
            x = x,
            y = y
        )
    }

}

private fun EcCurve.toCoseCurve(): CoseEllipticCurve = when (this) {
    EcCurve.SECP_256_R_1 -> CoseEllipticCurve.P256
    EcCurve.SECP_384_R_1 -> CoseEllipticCurve.P384
    EcCurve.SECP_521_R_1 -> CoseEllipticCurve.P521
}
