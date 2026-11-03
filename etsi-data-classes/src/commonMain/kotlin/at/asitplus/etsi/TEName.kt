package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TEName(
    /** Localized formal names of the entity responsible for the recognized services (TS 119 602, 6.5.1). */
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one TEName entry." }
    }

    constructor(vararg elements: MultilingualCharacterString): this(elements.toList())
}

