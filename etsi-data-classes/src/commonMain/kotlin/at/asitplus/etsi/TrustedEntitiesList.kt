package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TrustedEntitiesList(
    /** Trusted entities and their services recognized under the scheme (TS 119 602, 6.4). */
    private val list: List<TrustedEntity>,
): List<TrustedEntity> by list {
    init {
        require(list.isNotEmpty()) {
            "Expected list to be non-empty, but was empty."
        }
    }

    constructor(vararg elements: TrustedEntity): this(elements.toList())
}