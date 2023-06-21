package at.asitplus.wallet.lib.jws

import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64


object MultibaseHelper {

    private const val PREFIX_DID_KEY = "did:key"

    /**
     * Returns something like `did:key:mEpA...` with the [x] and [y] values appended in Base64.
     * This translates to `Base64(0x12, 0x90, EC-P-256-Key)`.
     * Note that `0x1290` is not an official Multicodec prefix, but there seems to be none for
     * uncompressed P-256 key. We can't use the compressed format, because decoding that would
     * require some EC Point math...
     */
    fun calcKeyId(curve: EcCurve, x: ByteArray, y: ByteArray): String? {
        if (curve != EcCurve.SECP_256_R_1)
            return null
        return "$PREFIX_DID_KEY:${multibaseWrapBase64(multicodecWrapP256(encodeP256Key(x, y)))}"
    }

    fun calcPublicKey(keyId: String): Pair<ByteArray, ByteArray>? {
        if (!keyId.startsWith("$PREFIX_DID_KEY:")) return null
        val stripped = keyId.removePrefix("$PREFIX_DID_KEY:")
        return decodeP256Key(multicodecDecode(multibaseDecode(stripped)))
    }

    private fun multibaseWrapBase64(it: ByteArray) = "m${it.encodeBase64()}"

    private fun multibaseDecode(it: String?) =
        if (it != null && it.startsWith("m")) {
            it.removePrefix("m").decodeBase64ToArray()
        } else null

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecWrapP256(it: ByteArray) = byteArrayOf(0x12.toByte(), 0x90.toByte()) + it

    // 0x1200 would be with compression, so we'll use 0x1290
    private fun multicodecDecode(it: ByteArray?) =
        if (it != null && it.size > 1 && it[0] == 0x12.toByte() && it[1] == 0x90.toByte()) {
            it.drop(2).toByteArray()
        } else null

    // No compression, because decompression would need some EC math
    private fun encodeP256Key(x: ByteArray, y: ByteArray) = x + y

    // No decompression, because that would need some EC math
    private fun decodeP256Key(it: ByteArray?): Pair<ByteArray, ByteArray>? {
        if (it == null) return null
        val half: Int = it.size.floorDiv(2)
        val x = it.sliceArray(0 until half)
        val y = it.sliceArray(half until it.size)
        return Pair(x, y)
    }
}