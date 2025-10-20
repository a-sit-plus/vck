package at.asitplus.wallet.lib.data

import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

class PresentationExchangeInputEvaluatorTest : FunSpec({

    lateinit var elementIdentifier: String
    lateinit var elementValue: String
    lateinit var simpleCredential: JsonObject
    lateinit var arrayCredential: JsonObject
    lateinit var objectCredential: JsonObject

    beforeEach {
        elementIdentifier = "p" + uuid4().bytes.encodeToString(Base16)
        elementValue = uuid4().bytes.encodeToString(Base16)
        simpleCredential = buildJsonObject {
            put(elementIdentifier, JsonPrimitive(elementValue))
        }
        arrayCredential = buildJsonObject {
            put(elementIdentifier, buildJsonArray {
                add(JsonPrimitive(elementValue))
            })
        }
        objectCredential = buildJsonObject {
            put(elementIdentifier, buildJsonObject {
                put(elementIdentifier, JsonPrimitive(elementValue))
            })
        }
    }

    test("simple credential matches constraint field with string filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringFilter(elementIdentifier),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array credential does not match constraint field with string filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringFilter(elementIdentifier),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("object credential does not match constraint field with string filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringFilter(elementIdentifier),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("simple credential matches constraint field with string filter and const") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringConstFilter(elementIdentifier, elementValue),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array credential does not match constraint field with string filter and const") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringConstFilter(elementIdentifier, elementValue),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("object credential does not match constraint field with string filter and const") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = stringConstFilter(elementIdentifier, elementValue),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("simple credential matches constraint field with array filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = arrayFilter(elementIdentifier),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array credential matches constraint field with array filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = arrayFilter(elementIdentifier),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("object credential does not match constraint field with array filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = arrayFilter(elementIdentifier),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("simple credential matches constraint field with object filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = objectFilter(elementIdentifier),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array credential does not match constraint field with object filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = objectFilter(elementIdentifier),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldBeEmpty()
        }
    }

    test("object credential matches constraint field with object filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = objectFilter(elementIdentifier),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("primitive credential matches constraint field with empty filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = emptyFilter(elementIdentifier),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array matches constraint field with empty filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = emptyFilter(elementIdentifier),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("object matches constraint field with empty filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = emptyFilter(elementIdentifier),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("primitive credential matches constraint field with null filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = nullFilter(elementIdentifier),
            credential = simpleCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("array credential matches constraint field with null filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = nullFilter(elementIdentifier),
            credential = arrayCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }

    test("object credential matches constraint field with null filter") {
        PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
            constraintField = nullFilter(elementIdentifier),
            credential = objectCredential,
            pathAuthorizationValidator = { true }
        ).apply {
            shouldHaveSize(1)
        }
    }
}
private fun arrayFilter(elementIdentifier: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
    filter = ConstraintFilter(
        type = "array",
    )
)

private fun objectFilter(elementIdentifier: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
    filter = ConstraintFilter(
        type = "object",
    )
)

private fun emptyFilter(elementIdentifier: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
    filter = ConstraintFilter()
)

private fun nullFilter(elementIdentifier: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
)

private fun stringConstFilter(elementIdentifier: String, elementValue: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
    filter = ConstraintFilter(
        type = "string",
        const = JsonPrimitive(elementValue)
    )
)

private fun stringFilter(elementIdentifier: String): ConstraintField = ConstraintField(
    path = listOf("$.$elementIdentifier"),
    filter = ConstraintFilter(
        type = "string",
    )
)
