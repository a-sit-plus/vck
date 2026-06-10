package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive

@Suppress("unused")
val SelectiveDisclosureConstraintsTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("identifier check") {
        SelectiveDisclosureConstraints.ALWAYS.identifier shouldBe "always"
        SelectiveDisclosureConstraints.ALLOWED.identifier shouldBe "allowed"
        SelectiveDisclosureConstraints.NEVER.identifier shouldBe "never"
    }

    testSuite("serialization") {
        data(SelectiveDisclosureConstraints.entries) test {
            Json.encodeToJsonElement(it).jsonPrimitive.content shouldBe it.identifier
        }
    }
}
