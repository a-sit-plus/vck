package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.data.validation.third_party.kotlin.collections.requireDistinctNotNull
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * Relevant references:
 * OID4VP 1.0, 6: credentials: REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1
 * that specify the requested Credentials.
 *
 * - DCQLCredentialQuery: Within the Authorization Request, the same id MUST NOT be present
 *  more than once.
 */
@Serializable
@JvmInline
value class DCQLCredentialQueryList<out DCQLCredentialQueryType: DCQLCredentialQuery>(
    private val list: NonEmptyList<DCQLCredentialQueryType>
): List<DCQLCredentialQueryType> by list {
    init {
        requireDistinctNotNull { it.id }
    }

    constructor(query: DCQLCredentialQueryType, vararg queries: DCQLCredentialQueryType) : this(listOf(query, *queries).toNonEmptyList())
}