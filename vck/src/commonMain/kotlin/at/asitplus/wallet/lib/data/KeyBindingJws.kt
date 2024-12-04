package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Key Binding JWT for SD-JWT, per spec [draft-ietf-oauth-selective-disclosure-jwt-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)
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
    val transactionDataHashes: Set<@Serializable(ByteArrayBase64UrlSerializer::class) ByteArray>? = null,

    /**
     * OID4VP: REQUIRED when this parameter was present in the `transaction_data` request parameter. String representing
     * the hash algorithm identifier used to calculate hashes in [transactionDataHashes] response parameter.
     */
    @SerialName("transaction_data_hashes_alg")
    val transactionDataHashesAlgorithm: String? = null,
) {

    fun serialize() = vckJsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyBindingJws

        if (issuedAt != other.issuedAt) return false
        if (audience != other.audience) return false
        if (challenge != other.challenge) return false
        if (!sdHash.contentEquals(other.sdHash)) return false
        if (transactionDataHashes != other.transactionDataHashes) return false
        if (transactionDataHashesAlgorithm != other.transactionDataHashesAlgorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuedAt?.hashCode() ?: 0
        result = 31 * result + audience.hashCode()
        result = 31 * result + challenge.hashCode()
        result = 31 * result + sdHash.contentHashCode()
        result = 31 * result + (transactionDataHashes?.hashCode() ?: 0)
        result = 31 * result + (transactionDataHashesAlgorithm?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            vckJsonSerializer.decodeFromString<KeyBindingJws>(it)
        }.wrap()
    }

}