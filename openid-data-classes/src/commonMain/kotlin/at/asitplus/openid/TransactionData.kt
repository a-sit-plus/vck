package at.asitplus.openid

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import io.ktor.utils.io.charsets.*
import io.ktor.utils.io.core.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive


/**
 * Denotes a JSON string containing a Base64Url encoded [TransactionData] element
 * This is useful in classes defined in OpenID4VP since JSON string representation is not
 * strongly standardized (normal vs pretty-print etc) so de-/serialization between
 * different parties with different serializer settings may lead to erroneous
 * request rejection.
 */
typealias TransactionDataBase64Url = JsonPrimitive

@Deprecated("Use digest()", ReplaceWith("digest(Digest.SHA256)"))
fun TransactionDataBase64Url.sha256(): ByteArray =
    Digest.SHA256.digest(this.content.toByteArray(Charsets.UTF_8))

fun TransactionDataBase64Url.digest(digest: Digest): ByteArray =
    digest.digest(content.toByteArray(Charsets.UTF_8))

/**
 * OID4VP Draft 24: OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed parameter
 * set with details about the transaction that the Verifier is requesting the End-User to authorize.
 */
@Serializable
sealed class TransactionData {
    /**
     * OID4VP: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used to
     * authorize this transaction. In Presentation Exchange, the string matches the `id` field in the Input Descriptor.
     * In the Digital Credentials Query Language, the string matches the id field in the Credential Query.
     * If there is more than one element in the array, the Wallet MUST use only one of the referenced Credentials for
     * transaction authorization.
     */
    @SerialName("credential_ids")
    abstract val credentialIds: Set<String>

    /**
     * OID4VP: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used to
     * calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash
     * algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry
     * or a value defined in another specification and/or profile of this specification. If this parameter is not
     * present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support the
     * `sha-256` hash algorithm.
     */
    abstract val transactionDataHashAlgorithms: Set<String>?
}
