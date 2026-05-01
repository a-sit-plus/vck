package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UriSchemeName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class ElectronicAddress(
    private val list: List<MultilingualPointer>
) : List<MultilingualPointer> by list {
    init {
        require(list.any {
            it.uniformResourceIdentifier.schemeName == Rfc3986UriSchemeName.Common.MAILTO
        }) {
            "Expected list to contain at least 1 e-mail address identified using the scheme `mailto`, but got $list."
        }
        require(list.any {
            it.uniformResourceIdentifier.schemeName == Rfc3986UriSchemeName.Common.HTTPS
        }) {
            "Expected list to contain at least 1 web-site, but got $list."
        }
    }

    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}


