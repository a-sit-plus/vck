package at.asitplus.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.io.encoding.Base64
import kotlin.io.encoding.Base64.PaddingOption
import kotlin.io.encoding.ExperimentalEncodingApi

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