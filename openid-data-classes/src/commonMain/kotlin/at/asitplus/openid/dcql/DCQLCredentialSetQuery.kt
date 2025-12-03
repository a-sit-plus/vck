package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 *  6.2. Credential Set Query
 *
 * A Credential Set Query is an object representing a request for one or more Credentials to satisfy a particular use
 * case with the Verifier.
 */
@Serializable
data class DCQLCredentialSetQuery(
    /**
     * REQUIRED. A non-empty array, where each value in the array is a list of Credential Query identifiers
     * representing one set of Credentials that satisfies the use case. The value of each element in the `options` array
     * is a non-empty array of identifiers which reference elements in `credentials`.
     */
    @SerialName("options")
    val options: NonEmptyList<List<DCQLCredentialQueryIdentifier>>,

    /**
     * OPTIONAL. A boolean which indicates whether this set of Credentials is required to satisfy the particular use
     * case at the Verifier. If omitted, the default value is `true`.
     */
    @SerialName("required")
    val required: Boolean = true,

    )