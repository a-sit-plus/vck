package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class OtherAssociatedBodies(
    private val list: List<AssociatedBody>
) : List<AssociatedBody> by list {
    constructor(vararg elements: AssociatedBody) : this(elements.toList())
}