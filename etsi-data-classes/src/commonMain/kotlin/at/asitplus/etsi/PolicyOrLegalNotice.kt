package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PolicyOrLegalNotice(
    /** Localized policy pointers or legal-notice texts governing the list (TS 119 602, 6.3.11). */
    private val list: List<PolicyOrLegalNoticeItem>,
) : List<PolicyOrLegalNoticeItem> by list {
    init {
        require(list.isNotEmpty()) { "Expected at least one PolicyOrLegalNotice entry." }
        require(list.all { it.policy != null } || list.all { it.legalNotice != null }) {
            "Expected only policy pointers or only legal notices."
        }
    }

    constructor(vararg elements: PolicyOrLegalNoticeItem): this(elements.toList())
}