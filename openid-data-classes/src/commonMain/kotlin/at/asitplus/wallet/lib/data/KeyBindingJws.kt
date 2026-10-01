package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.contentHashCodeIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlin.time.Instant

/**
 * Key Binding JWT for SD-JWT, per [RFC 9901](https://datatracker.ietf.org/doc/html/rfc9901#name-key-binding-jwt).
 */
@Serializable
data class KeyBindingJws(
    /**
     * RFC 9901: REQUIRED. The value of this claim MUST be the time at which the Key Binding JWT was issued using the
     * syntax defined in [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * RFC 9901: REQUIRED. The value MUST be a single string that identifies the intended receiver of the Key Binding
     * JWT. How the value is represented is up to the protocol used and is out of scope for this specification.
     */
    @SerialName("aud")
    val audience: String,

    /**
     * RFC 9901: REQUIRED. Ensures the freshness of the signature or its binding to the given transaction. The value
     * type of this claim MUST be a string. How this value is obtained is up to the protocol used and is out of scope
     * for this specification.
     */
    @SerialName("nonce")
    val challenge: String,

    /**
     * RFC 9901: REQUIRED. The base64url-encoded hash value over the Issuer-signed JWT and the selected Disclosures.
     * The hash value in the `sd_hash` claim binds the KB-JWT to the specific SD-JWT. The `sd_hash` value MUST be
     * computed over the US-ASCII bytes of the encoded SD-JWT, i.e., the Issuer-signed JWT, a tilde character, and zero
     * or more Disclosures selected for presentation to the Verifier, each followed by a tilde character:
     * `<Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~`
     * The bytes of the digest MUST then be base64url encoded.
     */
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