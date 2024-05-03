package at.asitplus.jsonpath.core

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.7.  Normalized Paths
 */
class NormalizedJsonPath(
    val segments: List<NormalizedJsonPathSegment> = listOf(),
) {
    constructor(vararg segments: NormalizedJsonPathSegment) : this(segments = segments.asList())
    operator fun plus(other: NormalizedJsonPath): NormalizedJsonPath {
        return NormalizedJsonPath(this.segments + other.segments)
    }

    override fun toString(): String {
        return "$${segments.joinToString("")}"
    }
}