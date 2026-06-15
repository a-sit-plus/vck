package at.asitplus.openid

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class OpenId4VciClaimsPathPointerSegmentIndex(
    val uint: UInt, // restricted because JSON numbers above Long.MAX_VALUE are often parsed as flaoting point numbers
) : OpenId4VciClaimsPathPointerSegment {
    override fun toString() = uint.toString()
}