package at.asitplus.wallet.lib.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class EncryptedResponse(
    /** Should be set to "dcapi" */
    val type: String,
    val encryptedResponseData: EncryptedResponseData,
) {
    init {
        require(type == "dcapi")
    }
}
