package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class DCAPIInfo(
    /** Base64EncryptionInfo contains the cbor encoded EncryptionInfo as
    a base64-url-without-padding string. */
    val base64EncryptionInfo: String,
    /** Serialized origin of the request as defined in
     * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin */
    val serializedOrigin: String
) {
    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<DCAPIInfo>(it)
        }.wrap()
    }

}