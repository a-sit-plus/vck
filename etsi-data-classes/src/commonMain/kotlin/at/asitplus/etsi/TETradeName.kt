package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TETradeName(
    /** Localized official registration identifiers or alternative names of the trusted entity (TS 119 602, 6.5.2). */
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one TETradeName entry." }
    }

    constructor(vararg elements: MultilingualCharacterString): this(elements.toList())
}