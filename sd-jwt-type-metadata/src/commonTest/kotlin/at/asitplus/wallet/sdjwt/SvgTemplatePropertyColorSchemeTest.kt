package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SvgTemplatePropertyColorSchemeTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SvgTemplatePropertyColorScheme.dark.name shouldBe "dark"
        SvgTemplatePropertyColorScheme.light.name shouldBe "light"
    }
}


