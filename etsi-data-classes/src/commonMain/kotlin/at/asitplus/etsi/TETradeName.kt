package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TETradeName(
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    constructor(vararg elements: MultilingualCharacterString): this(elements.toList())
}