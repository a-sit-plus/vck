package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC9449
import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlin.time.Instant

@Deprecated("Renamed", replaceWith = ReplaceWith("KeyBindingPayload"))
typealias KeyBindingJws = KeyBindingPayload

/**
 * Key Binding JWT for SD-JWT, per [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding-jwt).
 */
@Serializable
data class KeyBindingPayload(
    @SerialName(RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    override val issuedAt: Instant? = null,

    @SerialName(RFC7519.AUD)
    override val audience: String,

    @SerialName(RFC9449.NONCE)
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
) : JwtPayload {

    @Transient
    val transactionDataHashesAlgorithm = when (transactionDataHashesAlgorithmString) {
        null, SdJwtConstants.SHA_256 -> Digest.SHA256
        SdJwtConstants.SHA_384 -> Digest.SHA384
        SdJwtConstants.SHA_512 -> Digest.SHA512
        else -> throw IllegalArgumentException("Unsupported digest name $transactionDataHashesAlgorithmString")
    }

    override val issuer: String? = null
    override val subject: String? = null
    override val notBefore: Instant? = null
    override val expiration: Instant? = null
    override val jwtId: String? = null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KeyBindingJws

        if (issuedAt != other.issuedAt) return false
        if (audience != other.audience) return false
        if (challenge != other.challenge) return false
        if (!sdHash.contentEquals(other.sdHash)) return false
        if (transactionDataHashes != other.transactionDataHashes) return false
        if (transactionDataHashesAlgorithmString != other.transactionDataHashesAlgorithmString) return false
        if (transactionDataHashesAlgorithm != other.transactionDataHashesAlgorithm) return false
        if (issuer != other.issuer) return false
        if (subject != other.subject) return false
        if (notBefore != other.notBefore) return false
        if (expiration != other.expiration) return false
        if (jwtId != other.jwtId) return false

        return true
    }

    override fun hashCode(): Int {
        var result = issuedAt.hashCode()
        result = 31 * result + audience.hashCode()
        result = 31 * result + challenge.hashCode()
        result = 31 * result + sdHash.contentHashCode()
        result = 31 * result + transactionDataHashes.hashCode()
        result = 31 * result + transactionDataHashesAlgorithmString.hashCode()
        result = 31 * result + transactionDataHashesAlgorithm.hashCode()
        result = 31 * result + issuer.hashCode()
        result = 31 * result + subject.hashCode()
        result = 31 * result + notBefore.hashCode()
        result = 31 * result + expiration.hashCode()
        result = 31 * result + jwtId.hashCode()
        return result
    }

}