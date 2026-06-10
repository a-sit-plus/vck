package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val SvgTemplatePropertyImageOrientationTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        SvgTemplatePropertyImageOrientation.landscape.name shouldBe "landscape"
        SvgTemplatePropertyImageOrientation.portrait.name shouldBe "portrait"
    }
}

