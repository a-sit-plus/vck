package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * 2026-04-23
 * https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 * 6.3.4 Scheme operator name
 * Description:
 * The SchemeOperatorName component specifies the name of the entity in charge of establishing, publishing,
 * signing and maintaining the list of trusted entities.
 * Format:
 * The SchemeOperatorName component shall contain a sequence of multilingual character strings (see clause 6.1.4).
 * Semantics:
 * The name of the scheme operator shall be the formal name under which the associated legal entity or mandated entity
 * (e.g. for governmental administrative agencies) associated with the legal entity in charge of establishing, publishing and
 * maintaining the list of trusted entities operates.
 * It shall be the name used in formal legal registration or authorization and to which any formal communication should be
 * addressed.
 */
@Serializable
@JvmInline
value class SchemeOperatorName(
    private val list: List<MultilingualCharacterString>
): List<MultilingualCharacterString> by list {
    constructor(vararg elements: MultilingualCharacterString): this(elements.toList())
}
