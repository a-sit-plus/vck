package at.asitplus.openid

import kotlinx.serialization.ContextualSerializer
import kotlinx.serialization.PolymorphicSerializer
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
 * OID4VP Draft 24: OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed parameter
 * set with details about the transaction that the Verifier is requesting the End-User to authorize.
 *
 * SERIALIZATION:
 * This module does not contain a TransactionData implementation. This means all serialization is done either
 * via [ContextualSerializer] (for when the data class is used but not all data classes are known in this module)
 * or via [PolymorphicSerializer] (when all data class implementations are known). These can be defined as submodules of a serializer.
 * The contextual serializer can be overridden and the polymorphic scope can be extended.
 * For an example implementation refer to [at.asitplus.rqes.rdcJsonSerializer] found in Json.kt.
 * When vck-rqes is used the Initializer will copy this into vckJsonSerializer. In this case the contextual serializer is the default serializer
 * and the polymorphic serializer needs to be specified when necessary.
 */
interface TransactionData {
    /**
     * OID4VP: REQUIRED. Array of strings each referencing a Credential requested by the Verifier that can be used to
     * authorize this transaction. In Presentation Exchange, the string matches the `id` field in the Input Descriptor.
     * In the Digital Credentials Query Language, the string matches the id field in the Credential Query.
     * If there is more than one element in the array, the Wallet MUST use only one of the referenced Credentials for
     * transaction authorization.
     */
    val credentialIds: Set<String>?

    /**
     * OID4VP: OPTIONAL. Array of strings each representing a hash algorithm identifier, one of which MUST be used to
     * calculate hashes in transaction_data_hashes response parameter. The value of the identifier MUST be a hash
     * algorithm value from the "Hash Name String" column in the IANA "Named Information Hash Algorithm" registry
     * or a value defined in another specification and/or profile of this specification. If this parameter is not
     * present, a default value of sha-256 MUST be used. To promote interoperability, implementations MUST support the
     * `sha-256` hash algorithm.
     */
    val transactionDataHashAlgorithms: Set<String>?

    fun toBase64UrlString(): TransactionDataBase64Url
}