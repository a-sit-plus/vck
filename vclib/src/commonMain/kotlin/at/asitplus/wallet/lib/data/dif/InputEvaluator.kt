package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toJsonElement
import at.asitplus.wallet.lib.data.matchJsonPath
import io.github.aakira.napier.Napier
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull

/*
Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
 */

// May support different features, not sure if all of them fit into one elevator
interface InputEvaluator {
    data class FieldQueryResult(
        val jsonPath: List<String>,
        val value: JsonElement,
    )

    data class CandidateInputMatch(
        val fieldQueryResults: List<FieldQueryResult?>?,
    )

    fun evaluateMatch(
        inputDescriptor: InputDescriptor,
        credential: JsonElement
    ): CandidateInputMatch?
}

class StandardInputEvaluator : InputEvaluator {
    override fun evaluateMatch(
        inputDescriptor: InputDescriptor,
        credential: JsonElement
    ): InputEvaluator.CandidateInputMatch? {
        // filter by constraints
        val fieldQueryResults = inputDescriptor.constraints?.let { constraints ->
            val constraintFields = constraints.fields ?: listOf()
            val fieldQueryResults = constraintFields.map { field ->
                val fieldQueryResult = field.path.firstNotNullOfOrNull { jsonPath ->
                    val candidates = credential.matchJsonPath(jsonPath)
                    candidates.entries.firstOrNull { candidate ->
                        field.filter?.let {
                            candidate.value.satisfiesConstraintFilter(it)
                        } ?: true
                    }?.let {
                        InputEvaluator.FieldQueryResult(
                            jsonPath = it.key,
                            value = it.value,
                        )
                    }
                }
                if ((field.isOptional == false) and (fieldQueryResult == null)) {
                    return null
                }
                field.predicate?.let {
                    when (it) {
                        PredicateEnum.PREFERRED -> fieldQueryResult
                        PredicateEnum.REQUIRED -> TODO("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature")
                    }
                } ?: fieldQueryResult
            }
            fieldQueryResults
        } ?: listOf()

        return InputEvaluator.CandidateInputMatch(
            fieldQueryResults = fieldQueryResults,
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
        if(isMatch == false) {
            return false
        }
    }
    filter.pattern?.let {
        val isMatch = runCatching {
            Regex(it).matches((this as JsonPrimitive).content)
        }.getOrDefault(false)
        if(isMatch == false) {
            return false
        }
    }
    filter.enum?.let { enum ->
        val isMatch = runCatching {
            enum.any { value ->
                value == (this as JsonPrimitive).content
            }
        }.getOrDefault(false)
        if(isMatch == false) {
            return false
        }
    }
    // TODO: Implement support for other filters
    return true
}