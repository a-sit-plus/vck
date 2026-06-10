package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val W3cSubresourceIntegrityMetadataTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        W3cSubresourceIntegrityMetadata(
            "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        ).expression.run {
            algorithm shouldBe ContentSecurityPolicySourceExpressionHashAlgorithm.sha384
            hashValue.toString() shouldBe "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        }
        W3cSubresourceIntegrityMetadata(
            "sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        ).expression.run {
            algorithm shouldBe ContentSecurityPolicySourceExpressionHashAlgorithm.sha384
            hashValue.toString() shouldBe "H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO"
        }
    }
}

