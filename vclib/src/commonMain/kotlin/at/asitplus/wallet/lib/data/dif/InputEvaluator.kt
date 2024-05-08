package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import io.github.aakira.napier.Napier
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

    data class FieldQueryResult(
        val constraintField: ConstraintField,
        val match: NodeListEntry,
    )
    data class CandidateInputMatching(
        val fieldQueryResults: List<FieldQueryResult?>?,
    )

    fun evaluateMatch(
        inputDescriptor: InputDescriptor,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<CandidateInputMatching> {
        // filter by constraints
        val fieldQueryResults = inputDescriptor.constraints?.let { constraints ->
            val constraintFields = constraints.fields ?: listOf()
            val fieldQueryResults = constraintFields.map { field ->
                val fieldQueryResult = field.path.firstNotNullOfOrNull { jsonPath ->
                    val candidates = JsonPath(jsonPath).query(credential)
                    candidates.firstOrNull { candidate ->
                        if(pathAuthorizationValidator(candidate.normalizedJsonPath)) {
                            field.filter?.let {
                                candidate.value.satisfiesConstraintFilter(it)
                            } ?: true
                        } else false
                    }?.let {
                        InputEvaluator.FieldQueryResult(
                            constraintField = field,
                            match = it,
                        )
                    }
                }
                if ((field.optional != true) and (fieldQueryResult == null)) {
                    return KmmResult.failure(
                        FailedFieldQueryException(field)
                            .also { it.message?.let { Napier.d(it) } }
                    )
                }
                field.predicate?.let {
                    when (it) {
                        // TODO: RequirementEnum.NONE is not a valid field value, maybe change member type to new Enum?
                        RequirementEnum.NONE -> fieldQueryResult
                        RequirementEnum.PREFERRED -> fieldQueryResult
                        RequirementEnum.REQUIRED -> return KmmResult.failure(
                            MissingFeatureSupportException("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature")
                                .also { it.message?.let { Napier.d(it) } }
                        )
                    }
                } ?: fieldQueryResult
            }
            fieldQueryResults
        } ?: listOf()

        return KmmResult.success(
            CandidateInputMatching(
                fieldQueryResults = fieldQueryResults,
            )
        )
    }
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

            "boolean" -> this.isString == false && this.booleanOrNull != null
            "integer" -> this.isString == false && this.longOrNull != null
            "number" -> this.isString == false && this.doubleOrNull != null
            else -> false
        }
    }

    if (typeMatchesElement == false) {
        return false
    }

    filter.const?.let {
        val isMatch = runCatching {
            it == (this as JsonPrimitive).content
        }.getOrDefault(false)
        if (isMatch == false) {
            return false
        }
    }
    filter.pattern?.let {
        val isMatch = runCatching {
            Regex(it).matches((this as JsonPrimitive).content)
        }.getOrDefault(false)
        if (isMatch == false) {
            return false
        }
    }
    filter.enum?.let { enum ->
        val isMatch = runCatching {
            enum.any { value ->
                value == (this as JsonPrimitive).content
            }
        }.getOrDefault(false)
        if (isMatch == false) {
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