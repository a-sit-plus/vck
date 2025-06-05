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
data class EncryptedResponse(
    /** Should be set to "dcapi" */
    val type: String,
    val encryptedResponseData: EncryptedResponseData
) {
    init {
        require(type == "dcapi")
    }

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<EncryptedResponse>(it)
        }.wrap()
    }
}
