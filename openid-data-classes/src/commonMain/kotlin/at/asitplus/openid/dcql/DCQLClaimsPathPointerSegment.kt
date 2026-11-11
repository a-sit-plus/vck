package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/** A component of a claims path pointer (OpenID4VP 1.0, 7), processed by [DCQLClaimsPathPointer.query]. */
@Serializable(with = DCQLClaimsPathPointerSegmentSerializer::class)
sealed interface DCQLClaimsPathPointerSegment {
    @JvmInline
    value class NameSegment(val name: String) : DCQLClaimsPathPointerSegment {
        override fun toString(): String {
            return "NameSegment($name)"
        }
    }

    @JvmInline
    value class IndexSegment(val index: UInt) : DCQLClaimsPathPointerSegment {
        override fun toString(): String {
            return "IndexSegment($index)"
        }
    }

    data object NullSegment : DCQLClaimsPathPointerSegment {
        override fun toString(): String {
            return "NullSegment"
        }
    }
}
