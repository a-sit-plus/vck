package at.asitplus.etsi

import at.asitplus.rfc.CaseInsensitiveString
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * https://www.rfc-editor.org/rfc/rfc5646.html
 */
@Serializable
@JvmInline
value class Rfc5646LanguageTag(
    val caseInsensitiveString: CaseInsensitiveString,
) {
    init {
        // TODO: implement proper grammar validation?
    }

    constructor(string: String) : this(CaseInsensitiveString(string))

    val string: String
        get() = caseInsensitiveString.string
}




