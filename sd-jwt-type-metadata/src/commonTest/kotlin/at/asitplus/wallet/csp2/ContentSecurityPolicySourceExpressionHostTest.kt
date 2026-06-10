package at.asitplus.wallet.csp2

import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHash
import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHost
import at.asitplus.rfc3986uri.Rfc3986UriSchemeName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

@Suppress("unused")
val ContentSecurityPolicySourceExpressionHostTest by matrixSuite {
    /**
     * just making sure that the enum names remain consistent with the specification
     */
    test("values") {
        ContentSecurityPolicySourceExpressionHost(
            "https://example.com:443"
        ).run {
            path.shouldBeNull()
            port.shouldNotBeNull().string shouldBe "443"
            schemeName.shouldNotBeNull() shouldBe Rfc3986UriSchemeName.Common.HTTPS
            host.string shouldBe "example.com"
        }
    }
}