package at.asitplus.etsi

import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TEElectronicAddress(
    /** Localized email, website and optional telephone contact URIs of the trusted entity (TS 119 602, 6.5.3.2). */
    private val list: List<MultilingualPointer>
) : List<MultilingualPointer> by list {
    init {
        require(list.any {
            it.uniformResourceIdentifier.schemeName == Rfc3986UriSchemeName.Common.MAILTO
        }) {
            "Expected list to contain at least 1 e-mail address identified using the scheme `mailto`, but got $list."
        }
        /**
         * TODO: this validation is part of the specification, but some entries in the actual LoTEs don't provide a website
         */
//        require(list.any {
//            it.uniformResourceIdentifier.string.startsWith("https:")
//        }) {
//            "Expected list to contain at least 1 web-site, but got $list."
//        }
    }

    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}