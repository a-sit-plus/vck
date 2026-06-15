package at.asitplus.openid

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class OpenId4VciClaimsPathPointerSegmentString(
    val string: String
) : OpenId4VciClaimsPathPointerSegment {
    override fun toString() = string
}