package at.asitplus.wallet.csp2

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHash
import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val ContentSecurityPolicySourceExpressionHashTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        ContentSecurityPolicySourceExpressionHash(
            "'sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO'"
        ).run {
            algorithm shouldBe ContentSecurityPolicySourceExpressionHashAlgorithm.sha384
            hashValue.toString() shouldBe "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        }
    }
}