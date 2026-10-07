package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SchemeTypeCommunityRules(
    /** Localized pointers to scheme type, community and approval rules (TS 119 602, 6.3.9). */
    private val list: List<MultilingualPointer>
): List<MultilingualPointer> by list {
    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}