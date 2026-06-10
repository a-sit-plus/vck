package at.asitplus.wallet.csp2

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionKeywordContent
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val ContentSecurityPolicySourceExpressionKeywordContentTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        ContentSecurityPolicySourceExpressionKeywordContent.self.name shouldBe "self"
        ContentSecurityPolicySourceExpressionKeywordContent.`unsafe-inline`.name shouldBe "unsafe-inline"
        ContentSecurityPolicySourceExpressionKeywordContent.`unsafe-eval`.name shouldBe "unsafe-eval"
    }
}

