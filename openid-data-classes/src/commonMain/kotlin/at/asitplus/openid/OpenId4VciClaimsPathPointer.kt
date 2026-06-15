package at.asitplus.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.jvm.JvmName

/**
 *  A claims path pointer is a pointer into the Verifiable Credential, identifying one or more claims. A claims path
 *  pointer MUST be a non-empty array of strings, nulls and integers. A claims path pointer can be processed, which
 *  means it is applied to a credential. The results of processing are the referenced claims.
 */
@Serializable
@JvmInline
value class OpenId4VciClaimsPathPointer(
    private val segments: NonEmptyList<OpenId4VciClaimsPathPointerSegment?>,
) : List<OpenId4VciClaimsPathPointerSegment?> by segments {
    constructor(
        segment: OpenId4VciClaimsPathPointerSegment?,
        vararg segments: OpenId4VciClaimsPathPointerSegment?,
    ) : this(listOf(segment).plus(segments).toNonEmptyList())

    companion object {
        // platform declaration clash when specifying as secondary constructor
        @JvmName("createFromStrings")
        operator fun invoke(segments: List<String>) = OpenId4VciClaimsPathPointer(
            segments.map {
                OpenId4VciClaimsPathPointerSegmentString(it)
            }.toNonEmptyList()
        )
        // platform declaration clash when specifying as secondary constructor
        @JvmName("createFromUInts")
        operator fun invoke(segments: List<UInt>) = OpenId4VciClaimsPathPointer(
            segments.map {
                OpenId4VciClaimsPathPointerSegmentIndex(it)
            }.toNonEmptyList()
        )
    }

    constructor(startSegment: String, vararg segments: String) : this(
        (listOf(startSegment) + segments).map {
            OpenId4VciClaimsPathPointerSegmentString(it)
        }.toNonEmptyList()
    )

    @ExperimentalUnsignedTypes
    constructor(startSegment: UInt, vararg segments: UInt) : this(
        (listOf(startSegment) + segments).map {
            OpenId4VciClaimsPathPointerSegmentIndex(it)
        }.toNonEmptyList()
    )

    operator fun plus(other: Iterable<OpenId4VciClaimsPathPointerSegment?>) = OpenId4VciClaimsPathPointer(
        (segments + other).toNonEmptyList()
    )

    operator fun plus(segment: OpenId4VciClaimsPathPointerSegment?) = OpenId4VciClaimsPathPointer(
        (segments + segment).toNonEmptyList()
    )

    operator fun plus(string: String) = OpenId4VciClaimsPathPointer(
        (segments + OpenId4VciClaimsPathPointerSegmentString(string)).toNonEmptyList()
    )

    operator fun plus(uint: UInt) = OpenId4VciClaimsPathPointer(
        (segments + OpenId4VciClaimsPathPointerSegmentIndex(uint)).toNonEmptyList()
    )
}