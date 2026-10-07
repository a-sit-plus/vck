package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PolicyOrLegalNotice(
    /** Localized policy pointers or legal-notice texts governing the list (TS 119 602, 6.3.11). */
    private val list: List<PolicyOrLegalNoticeItem>,
) : List<PolicyOrLegalNoticeItem> by list {
    constructor(vararg elements: PolicyOrLegalNoticeItem): this(elements.toList())
}