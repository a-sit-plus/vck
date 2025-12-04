package at.asitplus.dcapi

import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of ISO 18013-7 Annex C
 */
@Serializable
@CborArray
data class EncryptedResponse(
    /** Should be set to `dcapi` */
    val type: String,
    val encryptedResponseData: EncryptedResponseData,
) : DCAPIResponseContent {
    init {
        require(type == TYPE_DCAPI)
    }
}