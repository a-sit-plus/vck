@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.data

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/**
 * A scalar `$.type` filter (see [at.asitplus.wallet.lib.RequestOptions]) must match VC-JWT credentials whose `type` is
 * an array and any VC carrying multiple types.
 */
val LegacyVcTypeConstraintTest by matrixSuite {

    fun typeConstraint(type: String) = Constraint(
        fields = setOf(
            ConstraintField(
                path = listOf("$.type"),
                filter = ConstraintFilter(type = "string", const = JsonPrimitive(type)),
            )
        )
    )

    "scalar type filter matches an entry of the VC type array" {
        val credential = buildJsonObject {
            put("type", JsonArray(listOf(JsonPrimitive("VerifiableCredential"), JsonPrimitive("AtomicAttribute2023"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(typeConstraint("AtomicAttribute2023"), credential) { true }
            .isSuccess shouldBe true
    }

    "scalar type filter does not match a type absent from the array" {
        val credential = buildJsonObject {
            put("type", JsonArray(listOf(JsonPrimitive("VerifiableCredential"), JsonPrimitive("AtomicAttribute2023"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(typeConstraint("SomeOtherCredential"), credential) { true }
            .isSuccess shouldBe false
    }

    // The array relaxation must stay scoped to the VC `type` field: a scalar constraint on another field must not be
    // silently satisfied by an array value (see PR #571 review).
    "scalar filter on a non-type field is not satisfied by an array value" {
        val statusConstraint = Constraint(
            fields = setOf(
                ConstraintField(
                    path = listOf("$.status"),
                    filter = ConstraintFilter(type = "string", const = JsonPrimitive("active")),
                )
            )
        )
        val credential = buildJsonObject {
            put("status", JsonArray(listOf(JsonPrimitive("active"), JsonPrimitive("revoked"))))
        }
        PresentationExchangeInputEvaluator
            .evaluateInputDescriptorConstraint(statusConstraint, credential) { true }
            .isSuccess shouldBe false
    }
}
