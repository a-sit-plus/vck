package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive

@Suppress("unused")
val SelectiveDisclosureConstraintsTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("identifier check") {
        SelectiveDisclosureConstraints.ALWAYS.identifier shouldBe "always"
        SelectiveDisclosureConstraints.ALLOWED.identifier shouldBe "allowed"
        SelectiveDisclosureConstraints.NEVER.identifier shouldBe "never"
    }

    testSuite("serialization") {
        withData(SelectiveDisclosureConstraints.entries) {
            Json.encodeToJsonElement(it).jsonPrimitive.content shouldBe it.identifier
        }
    }
}



