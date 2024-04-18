package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.data.jsonPath.JSONPathSelector
import at.asitplus.wallet.lib.data.jsonPath.jsonPathCompiler
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull

open class InputEvaluationException(message: String) : Exception(message)

class FailedFieldQueryException(val constraintField: ConstraintField) : InputEvaluationException(
    message = "No match has been found to satisfy constraint field: $constraintField"
)
class MissingFeatureSupportException(val featureName: String) : InputEvaluationException(
    message = "Feature is currently not supported: $featureName"
)

/*
Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
 */

// May support different features, not sure if all of them fit into one elevator
interface InputEvaluator {
    data class FieldQueryResult(
        val singularQuerySegmentSelectors: List<JSONPathSelector.SingularQuerySelector>,
        val value: JsonElement,
    )

    data class CandidateInputMatch(
        val fieldQueryResults: List<FieldQueryResult?>?,
    )

    fun evaluateMatch(
        inputDescriptor: InputDescriptor,
        credential: JsonElement
    ): KmmResult<CandidateInputMatch>
}

class StandardInputEvaluator : InputEvaluator {
    override fun evaluateMatch(
        inputDescriptor: InputDescriptor,
        credential: JsonElement
    ): KmmResult<InputEvaluator.CandidateInputMatch> {
        // filter by constraints
        val fieldQueryResults = inputDescriptor.constraints?.let { constraints ->
            val constraintFields = constraints.fields ?: listOf()
            val fieldQueryResults = constraintFields.map { field ->
                val fieldQueryResult = field.path.firstNotNullOfOrNull { jsonPath ->
                    val candidates = jsonPathCompiler.compile(jsonPath).invoke(credential)
                    candidates.firstOrNull { candidate ->
                        field.filter?.let {
                            candidate.value.satisfiesConstraintFilter(it)
                        } ?: true
                    }?.let {
                        InputEvaluator.FieldQueryResult(
                            singularQuerySegmentSelectors = it.singularQuerySelectors,
                            value = it.value,
                        )
                    }
                }
                if ((field.isOptional == false) and (fieldQueryResult == null)) {
                    return KmmResult.failure(
                        FailedFieldQueryException(field)
                            .also { it.message?.let { Napier.d(it) } }
                    )
                }
                field.predicate?.let {
                    when (it) {
                        PredicateEnum.PREFERRED -> fieldQueryResult
                        PredicateEnum.REQUIRED -> return KmmResult.failure(
                            MissingFeatureSupportException("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature")
                                .also { it.message?.let { Napier.d(it) } }
                        )
                    }
                } ?: fieldQueryResult
            }
            fieldQueryResults
        } ?: listOf()

        return KmmResult.success(
            InputEvaluator.CandidateInputMatch(
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
            "null" -> when (this) {
                JsonNull -> true
                else -> false
            }

            "boolean" -> this.booleanOrNull != null
            "integer" -> this.intOrNull != null
            "number" -> this.floatOrNull != null
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