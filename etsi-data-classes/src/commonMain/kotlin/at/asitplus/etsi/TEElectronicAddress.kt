package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TEElectronicAddress(
    /** Localized email, website and optional telephone contact URIs of the trusted entity (TS 119 602, 6.5.3.2). */
    private val list: List<MultilingualPointer>
) : List<MultilingualPointer> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one trusted-entity contact URI." }
        // TS 119 602, 6.5.3.2 refers to 6.3.5.2, which requires an e-mail address with the `mailto` scheme and a
        // web-site URI, and allows a telephone number with the `tel` scheme.
        // TODO This is not met by real-world data, e.g. https://development.trust.tech.ec.europa.eu/lists/eudiw/wrprc-providers.json
        //  lists only a website, and other lists only an e-mail address
//        require(list.any {
//            it.uniformResourceIdentifier.schemeName == Rfc3986UriSchemeName.Common.MAILTO
//        }) {
//            "Expected list to contain at least 1 e-mail address identified using the scheme `mailto`, but got $list."
//        }
//        require(list.any {
//            it.uniformResourceIdentifier.schemeName.string.lowercase() in setOf("http", "https")
//        }) { "Expected at least one website contact URI, but got $list." }
    }

    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}
