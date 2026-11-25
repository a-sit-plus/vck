package at.asitplus.wallet.ios

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val BuildersTest by matrixSuite {

    test("OpenId4VpHolderBuilder applies configuration") {
        val builder = OpenId4VpHolderBuilder().apply {
            clientId = "https://example.test/wallet"
            authorizationEndpoint = "openid4vp-test:"
        }

        val metadata = builder.build().metadata

        metadata.issuer shouldBe builder.clientId
        metadata.authorizationEndpoint shouldBe builder.authorizationEndpoint
    }

    test("HolderAgentBuilder builds with defaults") {
        val builder = HolderAgentBuilder()

        val holder = builder.build()

        holder shouldNotBe null
    }
}
