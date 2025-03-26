package at.asitplus.openid

/**
 * OID4VP Draft 24: OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed parameter
 * set with details about the transaction that the Verifier is requesting the End-User to authorize.
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
}