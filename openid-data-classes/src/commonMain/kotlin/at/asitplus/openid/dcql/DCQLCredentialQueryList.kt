package at.asitplus.openid.dcql

import at.asitplus.data.collections.NonEmptyList
import at.asitplus.data.collections.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.data.validation.third_party.kotlin.collections.requireDistinctNotNull
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * Relevant references:
 * OID4VP draft 23: A non-empty array of Credential Queries as defined in Section 6.1 that
 * specify the requested Verifiable Credentials.
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

    constructor(vararg queries: DCQLCredentialQueryType) : this(queries.toList().toNonEmptyList())
}