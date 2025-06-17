package at.asitplus.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class EncryptionInfo(
    /** Should be set to "dcapi" */
    val type: String,
    val encryptionParameters: EncryptionParameters
) {
    init {
        require(type == "dcapi")
    }
}