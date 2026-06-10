package at.asitplus.wallet.csp2

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val ContentSecurityPolicySourceExpressionHashAlgorithmTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        ContentSecurityPolicySourceExpressionHashAlgorithm.sha256.name shouldBe "sha256"
        ContentSecurityPolicySourceExpressionHashAlgorithm.sha384.name shouldBe "sha384"
        ContentSecurityPolicySourceExpressionHashAlgorithm.sha512.name shouldBe "sha512"
    }
}


