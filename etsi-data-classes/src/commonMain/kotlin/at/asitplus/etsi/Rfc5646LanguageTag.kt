package at.asitplus.etsi

import at.asitplus.rfc3986uri.CaseInsensitiveString
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * [RFC5646](https://datatracker.ietf.org/doc/html/rfc5646)
 */
@Serializable
@JvmInline
value class Rfc5646LanguageTag(
    /** RFC 5646 language tag stored with case-insensitive comparison (TS 119 612, 5.1.4). */
    val caseInsensitiveString: CaseInsensitiveString,
) {
    init {
        // TODO: implement proper grammar validation?
    }

    constructor(string: String) : this(CaseInsensitiveString(string))

    /** String representation of the language tag; ETSI serialization uses lowercase. */
    val string: String
        get() = caseInsensitiveString.string
}




