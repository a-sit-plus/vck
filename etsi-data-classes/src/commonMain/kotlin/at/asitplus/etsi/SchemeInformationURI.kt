package at.asitplus.etsi

import at.asitplus.etsi.PolicyOrLegalNotice
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class SchemeInformationURI(
    private val list: List<MultilingualPointer>
): List<MultilingualPointer> by list {
    constructor(vararg elements: MultilingualPointer): this(elements.toList())
}