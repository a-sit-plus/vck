package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PostalAddresses(
    private val list: List<PostalAddress>
) : List<PostalAddress> by list {
    constructor(vararg elements: PostalAddress) : this(elements.toList())
}