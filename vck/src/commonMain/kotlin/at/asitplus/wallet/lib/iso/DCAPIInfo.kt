package at.asitplus.wallet.lib.iso

import at.asitplus.iso.EncryptionInfo
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class DCAPIInfo(
    /** Base64EncryptionInfo contains the cbor encoded EncryptionInfo as
     * a base64-url-without-padding string.
     */
    val base64EncryptionInfo: String,
    /** Serialized origin of the request as defined in
     * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
     */
    val serializedOrigin: String,
) {
    companion object {
        fun create(encryptionInfo: EncryptionInfo, origin: String): DCAPIInfo =
            DCAPIInfo(
                base64EncryptionInfo = vckCborSerializer.encodeToByteArray(encryptionInfo)
                    .encodeToString(Base64UrlStrict),
                serializedOrigin = origin
            )
    }

}