package at.asitplus.wallet.sdjwt

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SelectiveDisclosureConstraintsTest by testSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SelectiveDisclosureConstraints.ALWAYS.name shouldBe "always"
        SelectiveDisclosureConstraints.ALLOWED.name shouldBe "allowed"
        SelectiveDisclosureConstraints.NEVER.name shouldBe "never"
    }
}



