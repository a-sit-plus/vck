package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PointersToOtherLoTE(
    /** References to other relevant lists of trusted entities or lists of such lists (TS 119 602, 6.3.13). */
    private val list: List<OtherLoTEPointer>
): List<OtherLoTEPointer> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one PointersToOtherLoTE entry." }
    }

    constructor(vararg elements: OtherLoTEPointer): this(elements.toList())
}