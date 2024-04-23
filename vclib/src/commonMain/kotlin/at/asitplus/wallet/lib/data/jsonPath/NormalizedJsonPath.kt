package at.asitplus.wallet.lib.data.jsonPath

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