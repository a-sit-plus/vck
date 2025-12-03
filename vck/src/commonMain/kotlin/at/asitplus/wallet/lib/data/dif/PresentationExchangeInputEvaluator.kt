package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.RequirementEnum
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.core.NodeListEntry
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.CredentialFormatEnum
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
 * Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation.
 *
 * Missing features:
 *  * `statuses` (Credential Status Constraint Feature)
 *  * `subject_is_issuer`, `is_holder`, `same_subject` (Relational Constraint Feature)
 *  * Predicate feature <https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature>
 *
 * Missing constraint filters:
 *  * Recursive type check
 *  * Element count check (minItems = 1) for root,
 *  * Check for unique items at root (whatever that means)
 */
object PresentationExchangeInputEvaluator {
    fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        fallbackFormatHolder: FormatHolder?,
        credentialClaimStructure: JsonElement,
        credentialFormat: CredentialFormatEnum,
        credentialScheme: String?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>> = catching {
        (inputDescriptor.format ?: fallbackFormatHolder)?.let { formatHolder ->
            if (credentialFormat !in formatHolder.toSupportedFormats()) {
                Napier.d("Credential format `$credentialFormat` is not supported by the relying party.")
                throw InvalidCredentialFormatException(credentialFormat, formatHolder.toSupportedFormats())
            }
        }

        if (credentialFormat == CredentialFormatEnum.MSO_MDOC) {
            val requiredCredentialScheme = inputDescriptor.id
            if (requiredCredentialScheme != credentialScheme) {
                Napier.d("Credential scheme `$credentialScheme` is not supported by the relying party.")
                throw InvalidCredentialSchemeException(credentialScheme, setOf(requiredCredentialScheme))
            }
        }

        inputDescriptor.constraints?.let {
            evaluateInputDescriptorConstraint(
                constraint = it,
                credentialClaimStructure = credentialClaimStructure,
                pathAuthorizationValidator = pathAuthorizationValidator,
            ).getOrThrow()
        } ?: mapOf()
    }

    private fun FormatHolder.toSupportedFormats(): List<CredentialFormatEnum> = listOf(
        jwtVp to CredentialFormatEnum.JWT_VC,
        sdJwt to CredentialFormatEnum.DC_SD_JWT,
        msoMdoc to CredentialFormatEnum.MSO_MDOC,
    ).filter {
        it.first != null
    }.map {
        it.second
    }

    fun evaluateInputDescriptorConstraint(
        constraint: Constraint,
        credentialClaimStructure: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>> = catching {
        val constraintFieldEvaluation = constraint.fields?.associateWith { field ->
            evaluateConstraintField(
                field = field,
                credential = credentialClaimStructure,
                pathAuthorizationValidator = pathAuthorizationValidator,
            )
        } ?: mapOf()

        if (constraintFieldEvaluation.values.any { it.isFailure }) {
            val failures = constraintFieldEvaluation
                .filter { it.value.isFailure }
            throw ConstraintFieldsEvaluationException(
                message = "Input descriptor constraint fields could not be satisfied: ${failures.details()}",
                constraintFieldExceptions = failures.mapValues {
                    it.value.exceptionOrNull()!!
                }
            )
        }

        constraintFieldEvaluation.mapValues {
            it.value.getOrThrow()
        }
    }

    private fun Map<ConstraintField, KmmResult<NodeList>>.details(): String =
        keys.joinToString { it.path.joinToString() }

    // filter by constraints
    fun evaluateConstraintField(
        field: ConstraintField,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<NodeList> = catching {
        val result = matchConstraintFieldPaths(
            constraintField = field,
            credential = credential,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )

        if (result.isEmpty() && field.optional != true) {
            throw FailedFieldQueryException(field)
                .also { Napier.v("evaluateFieldQueryResult failed", it) }
        }

        field.predicate
            ?.let { result.matchPredicate(field, it) }
            ?: result
    }

    private fun NodeList.matchPredicate(
        field: ConstraintField,
        enum: RequirementEnum
    ): List<NodeListEntry> {
        if (field.filter != null) {
            throw PredicateFeatureException("Predicate feature is used, but filter is not available.")
        }

        return when (enum) {
            // TODO: RequirementEnum.NONE is not a valid field value, maybe change member type to new Enum?
            RequirementEnum.NONE -> this
            RequirementEnum.PREFERRED -> this
            RequirementEnum.REQUIRED -> throw MissingFeatureSupportException("Predicate feature")
        }
    }

    // filter by constraints
    fun matchConstraintFieldPaths(
        constraintField: ConstraintField,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): NodeList = constraintField.path.flatMap { jsonPath ->
        credential.candidates(jsonPath).filter { candidate ->
            pathAuthorizationValidator(candidate.normalizedJsonPath) &&
                    constraintField.filter?.let { candidate.value.matchConstraints(it) } ?: true
        }
    }

    private fun JsonElement.candidates(jsonPath: String): NodeList =
        JsonPath(jsonPath).query(this)
}

internal fun JsonElement.matchConstraints(filter: ConstraintFilter): Boolean {
    if (!matchType(filter)) {
        return false
    }
    filter.const?.let {
        if (!matchConst(it))
            return false
    }
    filter.pattern?.let {
        if (!matchPattern(it))
            return false
    }
    filter.enum?.let { enum ->
        if (!matchEnum(enum))
            return false
    }
    return true
}

private fun JsonElement.matchType(filter: ConstraintFilter): Boolean = when (this) {
    is JsonArray -> filter.type == null || filter.type == "array"
    is JsonObject -> filter.type == null || filter.type == "object"
    is JsonPrimitive -> when (filter.type) {
        "string" -> this.isString
        "null" -> this == JsonNull
        "boolean" -> !this.isString && this.booleanOrNull != null
        "integer" -> !this.isString && this.longOrNull != null
        "number" -> !this.isString && this.doubleOrNull != null
        else -> true // no further filtering required
    }
}

private fun JsonElement.matchConst(primitive: JsonPrimitive) =
    catchingUnwrapped { primitive == this }
        .getOrDefault(false)

private fun JsonElement.matchPattern(string: String): Boolean =
    catchingUnwrapped { Regex(string).matches((this as JsonPrimitive).content) }
        .getOrDefault(false)

private fun JsonElement.matchEnum(enum: Collection<String>): Boolean =
    catchingUnwrapped { enum.any { it == (this as JsonPrimitive).content } }
        .getOrDefault(false)

open class InputEvaluationException(message: String) : Exception(message)

class InvalidCredentialFormatException(format: CredentialFormatEnum, expected: Collection<CredentialFormatEnum>) :
    Exception("Credential format `$format` does not match requirements: $expected")

class InvalidCredentialSchemeException(scheme: String?, expected: Collection<String?>) :
    Exception("Credential scheme `$scheme` does not match requirements: $expected")

open class ConstraintEvaluationException(message: String) : InputEvaluationException(message)

class ConstraintFieldsEvaluationException(
    message: String,
    val constraintFieldExceptions: Map<ConstraintField, Throwable>,
) : ConstraintEvaluationException(message)

open class ConstraintFieldEvaluationException(message: String) : InputEvaluationException(message)

class FailedFieldQueryException(val constraintField: ConstraintField) :
    ConstraintFieldEvaluationException("No match has been found to satisfy constraint field: $constraintField")

class MissingFeatureSupportException(val featureName: String) :
    ConstraintFieldEvaluationException("Feature is not supported: $featureName")

class PredicateFeatureException(message: String) : InputEvaluationException(message)