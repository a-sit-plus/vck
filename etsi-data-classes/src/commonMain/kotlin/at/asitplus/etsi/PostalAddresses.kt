package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PostalAddresses(
    /** Postal contact addresses in one or more languages (TS 119 612, 5.3.5.1). */
    private val list: List<PostalAddress>
) : List<PostalAddress> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one PostalAddresses entry." }
    }

    constructor(vararg elements: PostalAddress) : this(elements.toList())
}