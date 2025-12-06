package at.asitplus.dcapi

import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionInfoBase64UrlSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class DCAPIInfo(
    /** Base64EncryptionInfo contains the cbor encoded EncryptionInfo as
     * a base64-url-without-padding string.
     */
    @Serializable(with = EncryptionInfoBase64UrlSerializer::class)
    val encryptionInfo: EncryptionInfo,
    /** Serialized origin of the request as defined in
     * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
     */
    val serializedOrigin: String,
) : SessionTranscriptContentHashable