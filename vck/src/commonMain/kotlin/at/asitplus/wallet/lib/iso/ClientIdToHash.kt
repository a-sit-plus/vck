package at.asitplus.wallet.lib.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of the ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 */
@Serializable
@CborArray
data class ClientIdToHash(
    /** `client_id` from the authorization request */
    val clientId: String,
    /** Cryptographically random number with sufficient entropy (min. 16 bytes) */
    val mdocGeneratedNonce: String,
)