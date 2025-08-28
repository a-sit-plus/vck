package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  6.2. Credential Set Query
 *
 * A Credential Set Query is an object representing a request for one or more credentials to
 * satisfy a particular use case with the Verifier.
 */
@Serializable
data class DCQLCredentialSetQuery(
    /**
     * OID4VP draft 23: options: REQUIRED: A non-empty array, where each value in the array is a
     * list of Credential Query identifiers representing one set of Credentials that satisfies the
     * use case. The value of each element in the options array is an array of identifiers which
     * reference elements in credentials.
     */
    @SerialName("options")
    val options: NonEmptyList<List<DCQLCredentialQueryIdentifier>>,

    /**
     * OID4VP draft 23: required: OPTIONAL. A boolean which indicates whether this set of
     * Credentials is required to satisfy the particular use case at the Verifier. If omitted,
     * the default value is true.
     */
    @SerialName("required")
    val required: Boolean = true,

    /**
     * OID4VP draft 23: purpose: OPTIONAL. A string, number or object specifying the purpose of the
     * query. This specification does not define a specific structure or specific values for this
     * property. The purpose is intended to be used by the Verifier to communicate the reason for
     * the query to the Wallet. The Wallet MAY use this information to show the user the reason
     * for the request.
     */
    @Deprecated("Removed in OpenID Draft 26")
    @SerialName("purpose")
    val purpose: DCQLCredentialSetQueryPurpose? = null,
)