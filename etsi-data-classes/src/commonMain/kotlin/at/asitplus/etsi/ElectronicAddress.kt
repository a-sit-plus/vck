package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ElectronicAddress(
    /** Localized email, website and optional telephone contact URIs (TS 119 612, 5.3.5.2). */
    private val list: List<MultilingualPointer>
) : List<MultilingualPointer> by list {
    init {
        require(list.any {
            it.uniformResourceIdentifier.schemeName == Rfc3986UriSchemeName.Common.MAILTO
        }) {
            "Expected list to contain at least 1 e-mail address identified using the scheme `mailto`, but got $list."
        }
        require(list.any {
            it.uniformResourceIdentifier.schemeName.string.lowercase() in setOf("http", "https")
        }) { "Expected at least one website contact URI." }
    }

    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}


