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

/**
 * OID4VP: TransactionData is Base64URL encoded but the hash is taken over the string itself and should not be
 * Base64URL decoded before computing the hash. See lengthy discussion here
 *
 * https://github.com/openid/OpenID4VP/issues/457
 */
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
     * OID4VP Annex B.3.3.1: Optional hash algorithms for binding each transaction-data item into the SD-JWT VC Key
     * Binding JWT. For CSC QES signing and approval transactions, this binds the exact request data to the holder's
     * proof of possession. If absent, SHA-256 is used. Values are IANA hash names, and implementations must support
     * `sha-256`.
     */
    abstract val transactionDataHashAlgorithms: Set<String>?
}
