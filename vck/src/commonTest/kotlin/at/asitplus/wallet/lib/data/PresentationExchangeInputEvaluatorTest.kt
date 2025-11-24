package at.asitplus.wallet.lib.data

import at.asitplus.dif.ConstraintField
import at.asitplus.dif.ConstraintFilter
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

val PresentationExchangeInputEvaluatorTest by testSuite {

    withFixtureGenerator {
        object {
            val elementIdentifier = "p" + uuid4().bytes.encodeToString(Base16)
            val elementValue = uuid4().bytes.encodeToString(Base16)
            val simpleCredential = buildJsonObject {
                put(elementIdentifier, JsonPrimitive(elementValue))
            }
            val arrayCredential = buildJsonObject {
                put(elementIdentifier, buildJsonArray {
                    add(JsonPrimitive(elementValue))
                })
            }
            val objectCredential = buildJsonObject {
                put(elementIdentifier, buildJsonObject {
                    put(elementIdentifier, JsonPrimitive(elementValue))
                })
            }
        }
    } - {

        test("simple credential matches constraint field with string filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringFilter(it.elementIdentifier),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array credential does not match constraint field with string filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringFilter(it.elementIdentifier),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("object credential does not match constraint field with string filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringFilter(it.elementIdentifier),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("simple credential matches constraint field with string filter and const") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringConstFilter(it.elementIdentifier, it.elementValue),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array credential does not match constraint field with string filter and const") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringConstFilter(it.elementIdentifier, it.elementValue),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("object credential does not match constraint field with string filter and const") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = stringConstFilter(it.elementIdentifier, it.elementValue),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("simple credential matches constraint field with array filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = arrayFilter(it.elementIdentifier),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array credential matches constraint field with array filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = arrayFilter(it.elementIdentifier),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("object credential does not match constraint field with array filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = arrayFilter(it.elementIdentifier),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("simple credential matches constraint field with object filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = objectFilter(it.elementIdentifier),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array credential does not match constraint field with object filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = objectFilter(it.elementIdentifier),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldBeEmpty()
            }
        }

        test("object credential matches constraint field with object filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = objectFilter(it.elementIdentifier),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("primitive credential matches constraint field with empty filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = emptyFilter(it.elementIdentifier),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array matches constraint field with empty filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = emptyFilter(it.elementIdentifier),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("object matches constraint field with empty filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = emptyFilter(it.elementIdentifier),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("primitive credential matches constraint field with null filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = nullFilter(it.elementIdentifier),
               credential = it.simpleCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("array credential matches constraint field with null filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = nullFilter(it.elementIdentifier),
               credential = it.arrayCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
        }

        test("object credential matches constraint field with null filter") {
            PresentationExchangeInputEvaluator.matchConstraintFieldPaths(
                constraintField = nullFilter(it.elementIdentifier),
               credential = it.objectCredential,
                pathAuthorizationValidator = { true }
            ).apply {
                shouldHaveSize(1)
            }
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

private fun stringConstFilter(elementIdentifier: String, elementValue: String): ConstraintField =
    ConstraintField(
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