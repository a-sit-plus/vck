package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.data.validation.third_party.kotlin.collections.requireDistinctNotNull
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested
 * Credential.
 *
 * Relevant References:
 * - DCQLClaimQuery: Within the particular claims array, the same id MUST NOT be present more
 *  than once.
 */
@Serializable
@JvmInline
value class DCQLClaimsQueryList<out DCQLClaimsQueryType: DCQLClaimsQuery>(
    private val list: NonEmptyList<DCQLClaimsQueryType>
): List<DCQLClaimsQueryType> by list {
    init {
        requireDistinctNotNull { it.id }
    }

    constructor(vararg queries: DCQLClaimsQueryType) : this(queries.toList().toNonEmptyList())
}