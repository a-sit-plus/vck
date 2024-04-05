package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toJsonElement
import at.asitplus.wallet.lib.data.matchJsonPath
import kotlinx.serialization.json.JsonElement

/*
Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
 */

// May support different features, not sure if all of them fit into one elevator
interface InputEvaluator {
    data class CandidateInputMatch(
        val fieldQueryResults: List<FieldQueryResult?>?,
    )

    fun evaluateMatch(
        presentationDefinition: PresentationDefinition,
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry
    ): CandidateInputMatch?
}

class StandardInputEvaluator : InputEvaluator {
    override fun evaluateMatch(
        presentationDefinition: PresentationDefinition,
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry
    ): InputEvaluator.CandidateInputMatch? {
        // filter by credential format
        val supportedFormats = inputDescriptor.format ?: presentationDefinition.formats
        when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> if (supportedFormats?.jwtVp == null) {
                return null
            }

            is SubjectCredentialStore.StoreEntry.SdJwt -> if (supportedFormats?.jwtSd == null) {
                return null
            }

            is SubjectCredentialStore.StoreEntry.Iso -> if (supportedFormats?.msoMdoc == null) {
                return null
            }
        }

        // filter by constraints
        val fieldQueryResults = inputDescriptor.constraints?.let { constraints ->
            val constraintFields = constraints.fields ?: listOf()
            val fieldQueryResults = constraintFields.map { field ->
                val fieldQueryResult = field.path.firstNotNullOfOrNull { jsonPath ->
                    val candidates = credential.toJsonElement().matchJsonPath(jsonPath)
                    candidates.entries.firstOrNull { candidate ->
                        field.filter?.let {
                            candidate.value.satisfiesConstraintFilter(it)
                        } ?: true
                    }?.let {
                        FieldQueryResult(
                            jsonPath = it.key,
                            value = it.value,
                        )
                    }
                }
                if (field.isOptional == false and (fieldQueryResult == null)) {
                    return null
                }
                field.predicate?.let {
                    when(it) {
                        PredicateEnum.PREFERRED -> fieldQueryResult
                        PredicateEnum.REQUIRED -> TODO("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature")
                    }
                } ?: fieldQueryResult
            }
            if (fieldQueryResults.any { it == null }) {
                return null
            }
            fieldQueryResults
        } ?: listOf()

        return InputEvaluator.CandidateInputMatch(
            fieldQueryResults = fieldQueryResults,
        )
    }
}

data class FieldQueryResult(
    val jsonPath: List<String>,
    val value: JsonElement,
)

internal fun JsonElement.satisfiesConstraintFilter(filter: ConstraintFilter): Boolean {
    // TODO: properly implement constraint filter
    return true
}