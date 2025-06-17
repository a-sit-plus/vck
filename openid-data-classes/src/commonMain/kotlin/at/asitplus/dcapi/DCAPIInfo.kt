package at.asitplus.dcapi

import at.asitplus.iso.EncryptionInfo
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
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
     * a base64-url-without-padding string.
     */
    @Serializable(with = EncryptionInfoBase64UrlSerializer::class)
    val encryptionInfo: EncryptionInfo,
    /** Serialized origin of the request as defined in
     * https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin
     */
    val serializedOrigin: String,
)

object EncryptionInfoBase64UrlSerializer : TransformingSerializerTemplate<EncryptionInfo, String>(
    parent = String.serializer(),
    encodeAs = { coseCompliantSerializer.encodeToByteArray(it).encodeToString(Base64UrlStrict) },
    decodeAs = { coseCompliantSerializer.decodeFromByteArray<EncryptionInfo>(it.decodeToByteArray(Base64UrlStrict)) }
)
