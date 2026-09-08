package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.core.NormalizedJsonPath
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
sealed interface SingleClaimReference

@JvmInline
value class JsonClaimReference(
    val normalizedJsonPath: NormalizedJsonPath,
) : SingleClaimReference

@Serializable
data class MdocClaimReference(
    val namespace: String,
    val claimName: String,
) : SingleClaimReference
