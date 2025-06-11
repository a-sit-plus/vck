package at.asitplus.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborArray

/**
 * Part of the ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 */
@Serializable
@CborArray
data class ResponseUriToHash(
    /** `response_uri` from the authorization request */
    val responseUri: String,
    /** Cryptographically random number with sufficient entropy (min. 16 bytes) */
    val mdocGeneratedNonce: String,
)