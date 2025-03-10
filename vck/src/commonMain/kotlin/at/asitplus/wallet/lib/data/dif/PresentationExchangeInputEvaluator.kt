package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.RequirementEnum
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NodeList
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
 * Specification: https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-evaluation
 */
object PresentationExchangeInputEvaluator {
    fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        fallbackFormatHolder: FormatHolder?,
        credentialClaimStructure: JsonElement,
        credentialFormat: CredentialFormatEnum,
        credentialScheme: String?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>> = runCatching {
        (inputDescriptor.format ?: fallbackFormatHolder)?.let { formatHolder ->
            when(credentialFormat) {
                CredentialFormatEnum.JWT_VC -> formatHolder.jwtVp != null
                CredentialFormatEnum.VC_SD_JWT,
                CredentialFormatEnum.DC_SD_JWT -> formatHolder.jwtSd != null || formatHolder.sdJwt != null
                CredentialFormatEnum.MSO_MDOC -> formatHolder.msoMdoc != null
                else -> false
            }.let { isMatchingCredentialFormat ->
                if(!isMatchingCredentialFormat) {
                    throw InvalidCredentialFormatException()
                }
            }
        }

        when(credentialFormat) {
            CredentialFormatEnum.MSO_MDOC -> inputDescriptor.id
            else -> null
        }?.let { requiredCredentialScheme ->
            if(requiredCredentialScheme != credentialScheme) {
                throw InvalidCredentialSchemeException()
            }
        }

        inputDescriptor.constraints?.let {
            evaluateInputDescriptorConstraint(
                constraint = it,
                credentialClaimStructure = credentialClaimStructure,
                pathAuthorizationValidator = pathAuthorizationValidator,
            ).getOrThrow()
        } ?: mapOf()
    }.wrap()

    fun evaluateInputDescriptorConstraint(
        constraint: Constraint,
        credentialClaimStructure: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<ConstraintField, NodeList>> = runCatching {
        val constraintFieldEvaluation = constraint.fields?.associateWith { field ->
            evaluateConstraintField(
                field = field,
                credential = credentialClaimStructure,
                pathAuthorizationValidator = pathAuthorizationValidator,
            )
        } ?: mapOf()

        // TODO: statuses (Credential Status Constraint Feature)
        // TODO: subject_is_issuer, is_holder, same_subject (Relational Constraint Feature)

        if (constraintFieldEvaluation.values.any { it.isFailure }) {
            throw ConstraintFieldsEvaluationException(
                message = "Input descriptor constraint fields could not be satisfied.",
                constraintFieldExceptions = constraintFieldEvaluation.filter {
                    it.value.isFailure
                }.mapValues {
                    it.value.exceptionOrNull()!!
                }
            )
        }

        constraintFieldEvaluation.mapValues {
            it.value.getOrThrow()
        }
    }.wrap()

    // filter by constraints
    fun evaluateConstraintField(
        field: ConstraintField,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): KmmResult<NodeList> = runCatching {
        val fieldQueryResult = matchConstraintFieldPaths(
            constraintField = field,
            credential = credential,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )

        if (fieldQueryResult.isEmpty() && field.optional != true) {
            throw FailedFieldQueryException(field).also {
                Napier.v("evaluateFieldQueryResult failed", it)
            }
        }

        field.predicate?.let {
            if(field.filter != null) {
                throw PredicateFeatureException("Predicate feature is used, but filter is not available.")
            }

            when (it) {
                // TODO: RequirementEnum.NONE is not a valid field value, maybe change member type to new Enum?
                RequirementEnum.NONE -> fieldQueryResult
                RequirementEnum.PREFERRED -> fieldQueryResult
                RequirementEnum.REQUIRED -> throw MissingFeatureSupportException("Predicate feature from https://identity.foundation/presentation-exchange/spec/v2.0.0/#predicate-feature").also {
                    Napier.w("evaluateFieldQueryResult failed", it)
                }
            }
        } ?: fieldQueryResult
    }.wrap()

    // filter by constraints
    fun matchConstraintFieldPaths(
        constraintField: ConstraintField,
        credential: JsonElement,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ): NodeList = constraintField.path.flatMap { jsonPath ->
        val candidates = JsonPath(jsonPath).query(credential)
        candidates.filter { candidate ->
            pathAuthorizationValidator(candidate.normalizedJsonPath) && constraintField.filter?.let {
                candidate.value.satisfiesConstraintFilter(it)
            } ?: true
        }
    }
}

internal fun JsonElement.satisfiesConstraintFilter(filter: ConstraintFilter): Boolean {
    // TODO: properly implement constraint filter
    // source: https://json-schema.org/draft-07/schema#
    // this currently is only a tentative implementation
    val typeMatchesElement = when (this) {
        // TODO: need recursive type check; Need element count check (minItems = 1) for root, need check for unique items at root (whatever that means)
        is JsonArray -> filter.type == "array"
        is JsonObject -> filter.type == "object"
        is JsonPrimitive -> when (filter.type) {
            "string" -> this.isString
            "null" -> this == JsonNull
            "boolean" -> !this.isString && this.booleanOrNull != null
            "integer" -> !this.isString && this.longOrNull != null
            "number" -> !this.isString && this.doubleOrNull != null
            else -> true // no further filtering required
        }
    }

    if (!typeMatchesElement) {
        return false
    }

    filter.const?.let {
        val isMatch = runCatching {
            it == this
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

class InvalidCredentialFormatException : Exception("Credential format does not match requirements.")
class InvalidCredentialSchemeException : Exception("Credential scheme does not match requirements.")

open class ConstraintEvaluationException(message: String) : InputEvaluationException(message)

class ConstraintFieldsEvaluationException(message: String, constraintFieldExceptions: Map<ConstraintField, Throwable>) :
    ConstraintEvaluationException(message)

open class ConstraintFieldEvaluationException(message: String) : InputEvaluationException(message)

class FailedFieldQueryException(val constraintField: ConstraintField) : ConstraintFieldEvaluationException(
    "No match has been found to satisfy constraint field: $constraintField"
)

class MissingFeatureSupportException(val featureName: String) : ConstraintFieldEvaluationException(
    "Feature is not supported: $featureName"
)

class PredicateFeatureException(message: String) : InputEvaluationException(message)