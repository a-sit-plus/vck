package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlin.time.Instant

/**
 * Key Binding JWT for SD-JWT, per [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding-jwt).
 */
@Serializable
data class KeyBindingJws(
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    @SerialName("aud")
    val audience: String,

    @SerialName("nonce")
    val challenge: String,

    @SerialName("sd_hash")
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val sdHash: ByteArray,

    /**
     * OID4VP: Array of hashes, where each hash is calculated using a hash function over the strings received in the
     * `transaction_data` request parameter (see `SignatureRequestParameters`). Each hash value ensures the integrity
     * of, and maps to, the respective transaction data object.
     */
    @SerialName("transaction_data_hashes")
    val transactionDataHashes: List<@Serializable(ByteArrayBase64UrlSerializer::class) ByteArray>? = null,

    /**
     * OID4VP: REQUIRED when this parameter was present in the `transaction_data` request parameter. String representing
     * the hash algorithm identifier used to calculate hashes in [transactionDataHashes] response parameter.
     *
     * If not specified in the request, the hash function MUST be [SdJwtConstants.SHA_256].
     * Names are defined by IANA https://www.iana.org/assignments/named-information/named-information.xhtml
     */
    @SerialName("transaction_data_hashes_alg")
    val transactionDataHashesAlgorithmString: String? = null,
) {

    @Transient
    val transactionDataHashesAlgorithm = when (transactionDataHashesAlgorithmString) {
        null, SdJwtConstants.SHA_256 -> Digest.SHA256
        SdJwtConstants.SHA_384 -> Digest.SHA384
        SdJwtConstants.SHA_512 -> Digest.SHA512
        else -> throw IllegalArgumentException("Unsupported digest name $transactionDataHashesAlgorithmString")
    }

    @Suppress("DEPRECATION")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyBindingJws

        if (issuedAt != other.issuedAt) return false
        if (audience != other.audience) return false
        if (challenge != other.challenge) return false
        if (!sdHash.contentEquals(other.sdHash)) return false
        if (transactionDataHashes != null) {
            if (other.transactionDataHashes == null) return false
            if (!transactionDataHashes.contentEqualsIfArray(other.transactionDataHashes)) return false
        } else if (other.transactionDataHashes != null) return false
        if (transactionDataHashesAlgorithmString != other.transactionDataHashesAlgorithmString) return false

        return true
    }

    @Suppress("DEPRECATION")
    override fun hashCode(): Int {
        var result = issuedAt?.hashCode() ?: 0
        result = 31 * result + audience.hashCode()
        result = 31 * result + challenge.hashCode()
        result = 31 * result + sdHash.contentHashCode()
        result = 31 * result + (transactionDataHashes?.contentHashCodeIfArray() ?: 0)
        result = 31 * result + (transactionDataHashesAlgorithmString?.hashCode() ?: 0)
        return result
    }

}