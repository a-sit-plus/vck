package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SvgTemplatePropertyContrastTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SvgTemplatePropertyContrast.high.name shouldBe "high"
        SvgTemplatePropertyContrast.normal.name shouldBe "normal"
    }
}