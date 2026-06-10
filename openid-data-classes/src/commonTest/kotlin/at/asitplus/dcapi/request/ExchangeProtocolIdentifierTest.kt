package at.asitplus.dcapi.request

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe

val ExchangeProtocolIdentifierTest by matrixSuite {

    test("openid4vp v1 signed parses") {
        val identifier = ExchangeProtocolIdentifier.OpenId4VpV1Signed

        identifier.openIdVersion shouldBe "v1"
        identifier.openId4VpRequestType shouldBe "signed"
        identifier.isSignedOpenId4VpRequest shouldBe true
        identifier.isUnsignedOpenId4VpRequest shouldBe false
        identifier.isIsoMdocRequest shouldBe false
    }

    test("openid4vp v1 unsigned parses") {
        val identifier = ExchangeProtocolIdentifier.OpenId4VpV1Unsigned

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
        val identifier = ExchangeProtocolIdentifier.IsoMdocAnnexC

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
}
