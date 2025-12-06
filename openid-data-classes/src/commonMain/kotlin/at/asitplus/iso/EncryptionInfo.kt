package at.asitplus.iso

import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
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
data class EncryptionInfo(
    /** Should be set to `dcapi` */
    val type: String,
    val encryptionParameters: EncryptionParameters
) {
    init {
        require(type == TYPE_DCAPI)
    }
}

object EncryptionInfoBase64UrlSerializer : TransformingSerializerTemplate<EncryptionInfo, String>(
    parent = String.serializer(),
    encodeAs = { coseCompliantSerializer.encodeToByteArray(it).encodeToString(Base64UrlStrict) },
    decodeAs = { coseCompliantSerializer.decodeFromByteArray<EncryptionInfo>(it.decodeToByteArray(Base64UrlStrict)) }
)