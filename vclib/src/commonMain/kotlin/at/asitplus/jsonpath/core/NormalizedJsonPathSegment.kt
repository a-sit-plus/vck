package at.asitplus.jsonpath.core

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.7.  Normalized Paths
 */
sealed interface NormalizedJsonPathSegment {
    class NameSegment(val memberName: String) : NormalizedJsonPathSegment {
        override fun toString(): String {
            return "[${Rfc9535Utils.escapeToSingleQuotedStringLiteral(memberName)}]"
        }
    }
    class IndexSegment(val index: UInt) : NormalizedJsonPathSegment {
        override fun toString(): String {
            return "[$index]"
        }
    }
}