package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SchemeInformationURI(
    /** Localized pointers to information about the scheme (TS 119 602, 6.3.7). */
    private val list: List<MultilingualPointer>
): List<MultilingualPointer> by list {
    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}