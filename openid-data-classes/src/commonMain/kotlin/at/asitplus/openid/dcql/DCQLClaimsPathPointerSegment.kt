package at.asitplus.openid.dcql

import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NodeListEntry
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.jvm.JvmInline

@Serializable(with = DCQLClaimsPathPointerSegmentSerializer::class)
sealed interface DCQLClaimsPathPointerSegment {
    /**
     * Applies this component of a claims path pointer to the currently selected elements [nodeList], see
     * [DCQLClaimsPathPointer.query]. Returns an empty list if processing ends with an error, i.e. if any selected
     * element is not of the type this component requires.
     */
    fun query(nodeList: NodeList): NodeList

    @JvmInline
    value class NameSegment(val name: String) : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList): NodeList {
            if (nodeList.any { it.value !is JsonObject }) return emptyList()
            return nodeList.mapNotNull {
                it.value.jsonObject[name]?.let { value ->
                    NodeListEntry(normalizedJsonPath = it.normalizedJsonPath + name, value = value)
                }
            }
        }

        override fun toString(): String {
            return "NameSegment($name)"
        }
    }

    @JvmInline
    value class IndexSegment(val index: UInt) : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList): NodeList {
            if (nodeList.any { it.value !is JsonArray }) return emptyList()
            return nodeList.mapNotNull {
                val array = it.value.jsonArray
                if (index < array.size.toUInt()) {
                    NodeListEntry(normalizedJsonPath = it.normalizedJsonPath + index, value = array[index.toInt()])
                } else {
                    null
                }
            }
        }

        override fun toString(): String {
            return "IndexSegment($index)"
        }
    }

    data object NullSegment : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList): NodeList {
            if (nodeList.any { it.value !is JsonArray }) return emptyList()
            return nodeList.flatMap { claimQueryResult ->
                claimQueryResult.value.jsonArray.mapIndexed { index, jsonElement ->
                    NodeListEntry(
                        normalizedJsonPath = claimQueryResult.normalizedJsonPath + index.toUInt(),
                        value = jsonElement
                    )
                }
            }
        }

        override fun toString(): String {
            return "NullSegment"
        }
    }
}

