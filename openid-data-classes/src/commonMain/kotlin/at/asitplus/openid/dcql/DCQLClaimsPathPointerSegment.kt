package at.asitplus.openid.dcql

import at.asitplus.catching
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NodeListEntry
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.jvm.JvmInline

@Serializable(with = DCQLClaimsPathPointerSegmentSerializer::class)
sealed interface DCQLClaimsPathPointerSegment {
    fun query(nodeList: NodeList): NodeList

    @JvmInline
    value class NameSegment(val name: String) : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList) = nodeList.mapNotNull {
            catching {
                NodeListEntry(
                    normalizedJsonPath = it.normalizedJsonPath + name,
                    value = it.value.jsonObject[name]!!
                )
            }.getOrNull()
        }

        override fun toString(): String {
            return "NameSegment($name)"
        }
    }

    @JvmInline
    value class IndexSegment(val index: UInt) : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList) = nodeList.mapNotNull {
            catching {
                NodeListEntry(
                    normalizedJsonPath = it.normalizedJsonPath + index,
                    value = it.value.jsonArray[index.toInt()]
                )
            }.getOrNull()
        }

        override fun toString(): String {
            return "IndexSegment($index)"
        }
    }

    data object NullSegment : DCQLClaimsPathPointerSegment {
        override fun query(nodeList: NodeList) = nodeList.mapNotNull { claimQueryResult ->
            catching {
                claimQueryResult.value.jsonArray.mapIndexed { index, jsonElement ->
                    NodeListEntry(
                        normalizedJsonPath = claimQueryResult.normalizedJsonPath + index.toUInt(),
                        value = jsonElement
                    )
                }
            }.getOrNull()
        }.flatten()

        override fun toString(): String {
            return "NullSegment"
        }
    }
}

