package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PointersToOtherLoTE(
    private val list: List<OtherLoTEPointer>
): List<OtherLoTEPointer> by list {
    constructor(vararg elements: OtherLoTEPointer): this(elements.toList())
}