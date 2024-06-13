package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import io.github.aakira.napier.Napier
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
 */
class InputEvaluator {
    // filter by constraints
    fun evaluateConstraintFieldMatches(
        inputDescriptor: InputDescriptor,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>> = kotlin.runCatching {
        // filter by constraints
        inputDescriptor.constraints?.fields?.associateWith { field ->
            val fieldQueryResult = field.path.flatMap { jsonPath ->
                val candidates = JsonPath(jsonPath).query(credential)
                candidates.filter { candidate ->
                    if (pathAuthorizationValidator(candidate.normalizedJsonPath)) {
                        field.filter?.let {
                            candidate.value.satisfiesConstraintFilter(it)
                        } ?: true
                    } else false
                }
            }
            if (fieldQueryResult.isEmpty() && field.optional != true) {
                throw FailedFieldQueryException(field).also {
                    Napier.w("evaluateFieldQueryResult failed", it)
                }
            }
            field.predicate?.let {
                when (it) {
                    // TODO: RequirementEnum.NONE is not a valid field value, maybe change member type to new Enum?
                    RequirementEnum.NONE -> fieldQueryResult
                    RequirementEnum.PREFERRED -> fieldQueryResult
                    RequirementEnum.REQUIRED -> throw MissingFeatureSupportException("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature").also {
                        Napier.w("evaluateFieldQueryResult failed", it)
                    }
                }
            } ?: fieldQueryResult
        } ?: mapOf()
    }.wrap()
}

internal fun JsonElement.satisfiesConstraintFilter(filter: ConstraintFilter): Boolean {
    // TODO: properly implement constraint filter
    // source: https://json-schema.org/draft-07/schema#
    // this currently is only a tentative implementation
    val typeMatchesElement = when (this) {
        is JsonArray -> filter.type == "array" // TODO: need recursive type check; Need element count check (minItems = 1) for root, need check for unique items at root (whatever that means)
        is JsonObject -> filter.type == "object"
        is JsonPrimitive -> when (filter.type) {
            "string" -> this.isString
            "null" -> this == JsonNull
            "boolean" -> !this.isString && this.booleanOrNull != null
            "integer" -> !this.isString && this.longOrNull != null
            "number" -> !this.isString && this.doubleOrNull != null
            else -> false
        }
    }

    if (!typeMatchesElement) {
        return false
    }

    filter.const?.let {
        val isMatch = runCatching {
            it == (this as JsonPrimitive).content
        }.getOrDefault(false)
        if (!isMatch) {
            return false
        }
    }
    filter.pattern?.let {
        val isMatch = runCatching {
            Regex(it).matches((this as JsonPrimitive).content)
        }.getOrDefault(false)
        if (!isMatch) {
            return false
        }
    }
    filter.enum?.let { enum ->
        val isMatch = runCatching {
            enum.any { value ->
                value == (this as JsonPrimitive).content
            }
        }.getOrDefault(false)
        if (!isMatch) {
            return false
        }
    }
    // TODO: Implement support for other filters
    return true
}

open class InputEvaluationException(message: String) : Exception(message)

class FailedFieldQueryException(val constraintField: ConstraintField) : InputEvaluationException(
    "No match has been found to satisfy constraint field: $constraintField"
)

class MissingFeatureSupportException(val featureName: String) : InputEvaluationException(
    "Feature is not supported: $featureName"
)