package at.asitplus.etsi

import at.asitplus.etsi.PolicyOrLegalNotice
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * 2026-04-23
 * https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * 6.3.17 Scheme extensions
 * Description:
 * The SchemeExtensions component provides specific scheme-related information and enhancements that do not
 * require a change in the version identifier, which can be interpreted by all accessing parties according to the specific
 * scheme's rules.
 * Format:
 * The SchemeExtensions component shall contain a sequence of Scheme extensions whose format is left open. Each
 * extension shall have an indication of its criticality.
 * Semantics:
 * Each extension of the sequence shall be selected by the LoTESO according to the information it wishes to convey
 * within its LoTE. The meaning and value of each extension shall be defined by its source specifications being either the
 * LoTESOs own definition or any other extension definition produced by another entity, such as a community or
 * federation of schemes, a standards body, etc. The criticality indication shall have the same semantics as with extensions
 * in X.509-certificates [12]. A system using LoTEs shall reject the LoTE if it encounters a critical extension it does not
 * recognize, while a non-critical extension may be ignored if it is not recognized.
 */
@Serializable
@JvmInline
value class SchemeExtensions(
    private val list: List<SchemeExtension>
): List<SchemeExtension> by list {
    constructor(vararg elements: SchemeExtension): this(elements.toList())
}