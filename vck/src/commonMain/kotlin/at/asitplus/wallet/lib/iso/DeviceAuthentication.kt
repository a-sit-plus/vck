package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: mdoc authentication (9.1.3.4).
 *
 * Serialized as a byte string, wrapped in CBOR Tag 24, used as detached payload for [DeviceAuth.deviceSignature].
 */
@Serializable
@CborArray
data class DeviceAuthentication(
    /** Set to `DeviceAuthentication` */
    val type: String,
    val sessionTranscript: SessionTranscript,
    /** Same as in [Document.docType] */
    val docType: String,
    /** Same as in [DeviceSigned.namespaces] */
    @ValueTags(24U)
    val namespaces: ByteStringWrapper<DeviceNameSpaces>,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<DeviceAuthentication>(it)
        }.wrap()
    }
}