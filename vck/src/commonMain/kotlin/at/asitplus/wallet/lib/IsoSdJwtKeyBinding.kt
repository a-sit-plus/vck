package at.asitplus.wallet.lib

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.supreme.hash.digest
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.encodeToByteArray

/**
 * The claims of the key binding JWT of an SD-JWT VC presented in an ISO/IEC 18013-5 `DeviceResponse`, which bind it to
 * the session and the reader (WG10 N2933 v2, "About SD-JWT and SD-JWT+Key Binding"). Holder and reader derive them
 * alike.
 */
object IsoSdJwtKeyBinding {

    /** `aud` of a request without reader authentication. */
    const val AUDIENCE_WITHOUT_READER_AUTHENTICATION = "none"

    /** `nonce`: the base64url encoded (without padding) SHA-256 hash of `SessionTranscriptBytes`. */
    fun nonce(sessionTranscript: SessionTranscript): String =
        Digest.SHA256.digest(sessionTranscript.sessionTranscriptBytes()).encodeToString(Base64UrlStrict)

    /**
     * `aud` for the document request at [docRequestIndex] of [deviceRequest]: the base64url encoded (without padding)
     * SHA-256 hash of `#6.24 [+ReaderAuthAll]` if the request has `readerAuthAll`, otherwise of the `ReaderAuth` of
     * that document request, otherwise [AUDIENCE_WITHOUT_READER_AUTHENTICATION].
     *
     * The structures are hashed in their encoding by VC-K, as the request does not keep the bytes it was received in,
     * so a reader encoding them differently, e.g. their protected headers, derives another `aud`. N2933 v2 does not
     * settle which bytes are hashed either.
     */
    fun audience(deviceRequest: DeviceRequest, docRequestIndex: Int): String {
        deviceRequest.readerAuthAll?.let { readerAuthAll ->
            val encoded = coseCompliantSerializer.encodeToByteArray(readerAuthAll)
            return sha256(coseCompliantSerializer.encodeToByteArray(encoded).wrapInCborTag(24))
        }
        val readerAuth = deviceRequest.docRequests[docRequestIndex].readerAuth
            ?: return AUDIENCE_WITHOUT_READER_AUTHENTICATION
        return sha256(coseCompliantSerializer.encodeToByteArray(readerAuth))
    }

    private fun sha256(input: ByteArray) = Digest.SHA256.digest(input).encodeToString(Base64UrlStrict)
}
