package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 *  6.4. Claims Path Pointer
 *
 * A claims path pointer is a pointer into the JSON structure of the Verifiable Credential,
 * identifying one or more claims. A claims path pointer MUST be a non-empty array of strings and
 * non-negative integers. A string value indicates that the respective key is to be selected, a
 * null value indicates that all elements of the currently selected array(s) are to be selected;
 * and a non-negative integer indicates that the respective index in an array is to be selected.
 * The path is formed as follows:
 * Start with an empty array and repeat the following until the full path is formed.
 * To address a particular claim within an object, append the key (claim name) to the array.
 * To address an element within an array, append the index to the array (as a non-negative, 0-based
 * integer).To address all elements within an array, append a null value to the array. Verifiers
 * MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such
 * duplicate claim queries.
 */
@Serializable(with = DCQLClaimsPathPointerInlineSerializer::class)
class DCQLClaimsPathPointer(
    val segments: NonEmptyList<DCQLClaimsPathPointerSegment>,
): List<DCQLClaimsPathPointerSegment> by segments {
    constructor(vararg segments: DCQLClaimsPathPointerSegment) : this(segments.toList().toNonEmptyList())

    constructor(startSegment: String) : this(
        DCQLClaimsPathPointerSegment.NameSegment(startSegment)
    )

    constructor(startSegment: String, vararg segments: String) : this(
        (listOf(startSegment) + segments.toList()).map { DCQLClaimsPathPointerSegment.NameSegment(it) }.toNonEmptyList()
    )

    constructor(startSegment: UInt) : this(
        DCQLClaimsPathPointerSegment.IndexSegment(startSegment)
    )

    constructor(@Suppress("UNUSED_PARAMETER") nullValue: Nothing?) : this(
        DCQLClaimsPathPointerSegment.NullSegment
    )


    operator fun plus(other: DCQLClaimsPathPointer) = DCQLClaimsPathPointer(
        (segments + other.segments).toNonEmptyList()
    )

    operator fun plus(key: String) = DCQLClaimsPathPointer(
        (segments + DCQLClaimsPathPointerSegment.NameSegment(key)).toNonEmptyList()
    )

    operator fun plus(index: UInt) = DCQLClaimsPathPointer(
        (segments + DCQLClaimsPathPointerSegment.IndexSegment(index)).toNonEmptyList()
    )

    operator fun plus(@Suppress("UNUSED_PARAMETER") nullValue: Nothing?) = DCQLClaimsPathPointer(
        (segments + DCQLClaimsPathPointerSegment.NullSegment).toNonEmptyList()
    )


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
     *  6.4.1. Processing
     *
     * In detail, the array is processed by the Wallet from left to right as follows:
     * Select the root element of the Credential, i.e., the top-level JSON object.
     *
     * Process the query of the claims path pointer array from left to right:
     * If the component is a string, select the element in the respective key in the currently
     * selected element(s). If any of the currently selected element(s) is not an object, abort
     * processing and return an error. If the key does not exist in any element currently selected,
     * remove that element from the selection.
     *
     * If the component is null, select all elements of the currently selected array(s). If any of
     * the currently selected element(s) is not an array, abort processing and return an error.If
     * the component is a non-negative integer, select the element at the respective index in the
     * currently selected array(s). If any of the currently selected element(s) is not an array,
     * abort processing and return an error. If the index does not exist in a selected array,
     * remove that array from the selection.If the set of elements currently selected is empty,
     * abort processing and return an error.The result of the processing is the set of elements
     * which is requested for presentation.
     */
    fun query(jsonElement: JsonElement): NodeList {
        var nodeList = listOf(NodeListEntry(NormalizedJsonPath(), jsonElement))
        segments.forEach {
            nodeList = it.query(nodeList)
        }
        return nodeList
    }
}

