package at.asitplus.etsi

import at.asitplus.etsi.PolicyOrLegalNoticeItem
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class TrustedEntitiesList(
    private val list: List<TrustedEntity>,
): List<TrustedEntity> by list {
    init {
        require(list.isNotEmpty()) {
            "Expected list to be non-empty, but was empty."
        }
    }

    constructor(vararg elements: TrustedEntity): this(elements.toList())
}