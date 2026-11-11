package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * OpenID4VP 1.0, 7. Claims Path Pointer
 *
 * A claims path pointer is a pointer into the Credential, identifying one or more claims. A claims path pointer MUST
 * be a non-empty array of strings, nulls and non-negative integers. A claims path pointer can be processed, which
 * means it is applied to a Credential. The results of processing are the referenced claims.
 *
 * OpenID4VP 1.0, 7.1. Semantics for JSON-based credentials
 *
 * This section defines the semantics of a claims path pointer when applied to a JSON-based Credential.
 *
 * A string value indicates that the respective key is to be selected, a null value indicates that all elements of the
 * currently selected array(s) are to be selected; and a non-negative integer indicates that the respective index in an
 * array is to be selected. The path is formed as follows:
 *
 * Start with an empty array and repeat the following until the full path is formed.
 *
 *     To address a particular claim within an object, append the key (claim name) to the array.
 *     To address an element within an array, append the index to the array (as a non-negative, 0-based integer).
 *     To address all elements within an array, append a null value to the array.
 */
@Serializable(with = DCQLClaimsPathPointerInlineSerializer::class)
class DCQLClaimsPathPointer(
    val segments: NonEmptyList<DCQLClaimsPathPointerSegment>,
) : List<DCQLClaimsPathPointerSegment> by segments {
    constructor(vararg segments: DCQLClaimsPathPointerSegment)
            : this(segments.toList().toNonEmptyList())

    constructor(startSegment: String)
            : this(NameSegment(startSegment))

    constructor(startSegment: String, vararg segments: String)
            : this((listOf(startSegment) + segments.toList()).map { NameSegment(it) }.toNonEmptyList())

    constructor(startSegment: UInt)
            : this(IndexSegment(startSegment))

    constructor(@Suppress("UNUSED_PARAMETER") nullValue: Nothing?)
            : this(NullSegment)

    operator fun plus(other: DCQLClaimsPathPointer) =
        DCQLClaimsPathPointer((segments + other.segments).toNonEmptyList())

    operator fun plus(key: String) =
        DCQLClaimsPathPointer((segments + NameSegment(key)).toNonEmptyList())

    operator fun plus(index: UInt) =
        DCQLClaimsPathPointer((segments + IndexSegment(index)).toNonEmptyList())

    operator fun plus(@Suppress("UNUSED_PARAMETER") nullValue: Nothing?) =
        DCQLClaimsPathPointer((segments + NullSegment).toNonEmptyList())

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as DCQLClaimsPathPointer

        return segments == other.segments
    }

    override fun hashCode(): Int {
        return segments.hashCode()
    }

    override fun toString(): String {
        return "DCQLClaimsPathPointer($segments)"
    }

    /**
     * Selects the claims this claims path pointer points to in [jsonElement], the root element of a credential, i.e.
     * its top-level JSON object.
     *
     * OpenID4VP 1.0, 7.1.1. Processing:
     * In detail, the array is processed from left to right as follows:
     *
     * 1. Select the root element of the Credential, i.e., the top-level JSON object.
     * 2. Process the query of the claims path pointer array from left to right:
     *    1. If the component is a string, select the element in the respective key in the currently selected
     *       element(s). If any of the currently selected element(s) is not an object, abort processing and return an
     *       error. If the key does not exist in any element currently selected, remove that element from the
     *       selection.
     *    2. If the component is null, select all elements of the currently selected array(s). If any of the currently
     *       selected element(s) is not an array, abort processing and return an error.
     *    3. If the component is a non-negative integer, select the element at the respective index in the currently
     *       selected array(s). If any of the currently selected element(s) is not an array, abort processing and
     *       return an error. If the index does not exist in a selected array, remove that array from the selection.
     *    4. If the component is anything else, abort processing and return an error.
     * 3. If the set of elements currently selected is empty, abort processing and return an error.
     *
     * The result of the processing is the set of selected JSON elements.
     *
     * Each selected element is returned with its [DCQLSelectedClaim.path], the concrete position it was selected at:
     * a name for each string component, and the index of the element for each null or integer component.
     *
     * A component of any other type is rejected when the pointer is deserialized, see
     * [DCQLClaimsPathPointerSegmentSerializer].
     *
     * Every error results in an empty list, which callers treat as the claim not being present: a selected element
     * of the wrong type fails the whole pointer, even if other selected elements would continue, e.g. a wildcard over
     * an array whose elements are objects and strings. As an error of this claim only, it does not fail other options
     * of `claim_sets` that do not request the claim.
     */
    fun query(jsonElement: JsonElement): List<DCQLSelectedClaim> = segments
        .fold(listOf(Selected(listOf(), jsonElement))) { selection, segment -> selection.select(segment) }
        .map { DCQLSelectedClaim(DCQLClaimsPathPointer(it.path.toNonEmptyList()), it.value) }
}

/** An element selected while processing a claims path pointer, at the concrete [path] processed so far. */
private class Selected(val path: List<DCQLClaimsPathPointerSegment>, val value: JsonElement)

/** One step of OpenID4VP 1.0, 7.1.1 for [segment]; an error yields an empty selection. */
private fun List<Selected>.select(segment: DCQLClaimsPathPointerSegment): List<Selected> = when (segment) {
    // 2.1: "If any of the currently selected element(s) is not an object, abort processing and return an error. If the
    // key does not exist in any element currently selected, remove that element from the selection."
    is NameSegment -> if (any { it.value !is JsonObject }) listOf() else mapNotNull { selected ->
        (selected.value as JsonObject)[segment.name]?.let { Selected(selected.path + segment, it) }
    }

    // 2.2: "If any of the currently selected element(s) is not an array, abort processing and return an error."
    NullSegment -> if (any { it.value !is JsonArray }) listOf() else flatMap { selected ->
        (selected.value as JsonArray).mapIndexed { index, element ->
            Selected(selected.path + IndexSegment(index.toUInt()), element)
        }
    }

    // 2.3: "If any of the currently selected element(s) is not an array, abort processing and return an error. If the
    // index does not exist in a selected array, remove that array from the selection."
    is IndexSegment -> if (any { it.value !is JsonArray }) listOf() else mapNotNull { selected ->
        val array = selected.value as JsonArray
        if (segment.index < array.size.toUInt()) Selected(selected.path + segment, array[segment.index.toInt()])
        else null
    }
}

