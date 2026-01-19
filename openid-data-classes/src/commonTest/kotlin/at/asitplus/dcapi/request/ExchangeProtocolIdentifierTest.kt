package at.asitplus.dcapi.request

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val ExchangeProtocolIdentifierTest by testSuite {

    test("openid4vp v1 signed parses") {
        val identifier = ExchangeProtocolIdentifier.OPENID4VP_V1_SIGNED

        identifier.openIdVersion shouldBe "v1"
        identifier.openId4VpRequestType shouldBe "signed"
        identifier.isSignedOpenId4VpRequest shouldBe true
        identifier.isUnsignedOpenId4VpRequest shouldBe false
        identifier.isIsoMdocRequest shouldBe false
    }

    test("openid4vp v1 unsigned parses") {
        val identifier = ExchangeProtocolIdentifier.OPENID4VP_V1_UNSIGNED

        identifier.openIdVersion shouldBe "v1"
        identifier.openId4VpRequestType shouldBe "unsigned"
        identifier.isSignedOpenId4VpRequest shouldBe false
        identifier.isUnsignedOpenId4VpRequest shouldBe true
        identifier.isIsoMdocRequest shouldBe false
    }

    test("draft openid4vp protocol is accepted") {
        val identifier = ExchangeProtocolIdentifier("openid4vp")

        identifier.openIdVersion shouldBe null
        identifier.openId4VpRequestType shouldBe null
        identifier.isSignedOpenId4VpRequest shouldBe false
        identifier.isUnsignedOpenId4VpRequest shouldBe false
    }

    test("iso mdoc protocol is accepted") {
        val identifier = ExchangeProtocolIdentifier.ISO_MDOC_ANNEX_C

        identifier.isIsoMdocRequest shouldBe true
        identifier.openIdVersion shouldBe null
        identifier.openId4VpRequestType shouldBe null
        identifier.isSignedOpenId4VpRequest shouldBe false
        identifier.isUnsignedOpenId4VpRequest shouldBe false
    }

    test("invalid openid4vp version rejects") {
        shouldThrowAny {
            ExchangeProtocolIdentifier("openid4vp-v2-signed")
        }
    }

    test("multisigned openid4vp rejects") {
        shouldThrowAny {
            ExchangeProtocolIdentifier("openid4vp-v1-multisigned")
        }
    }
}
