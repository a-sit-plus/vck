package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class AssociatedBodyInformationExtensions(
    /** Sequence of additional information items for an associated body (TS 119 602, 6.5.5.1.7). */
    private val list: List<AssociatedBodyInformationExtension>
): List<AssociatedBodyInformationExtension> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one AssociatedBodyInformationExtensions entry." }
    }
}

