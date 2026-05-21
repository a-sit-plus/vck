package at.asitplus.dcapi.request

import at.asitplus.dcapi.request.verifier.testIsoMdocRequest
import at.asitplus.dcapi.request.verifier.testSignedOpenId4VpRequest
import at.asitplus.dcapi.request.verifier.testUnsignedOpenId4VpRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsFlattened
import at.asitplus.signum.indispensable.josef.JwsGeneralTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsFlattened
import at.asitplus.signum.indispensable.josef.toJwsGeneral
import at.asitplus.signum.indispensable.josef.typed
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf

private typealias IsoMdocRequestParametersFrom =
    RequestParametersFrom<RequestParametersFrom.IsoMdoc.IsoMdocRequestWrapper>

val DCAPIWalletRequestSerializationTest by testSuite {
    test("openid4vp unsigned request round-trips") {
        val parameters = testUnsignedOpenId4VpRequest.data
        val request = RequestParametersFrom.OpenId4VpUnsigned(
            parameters = parameters,
            jsonString = joseCompliantSerializer.encodeToString(parameters),
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded =
            joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(request)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded =
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(encoded)

        decoded shouldBe request
    }

    test("openid4vp signed request round-trips") {
        val request: JwsCompactTyped<AuthenticationRequestParameters> = testSignedOpenId4VpRequest.data.request.typed()
        val walletRequest = RequestParametersFrom.OpenId4VpSigned(
            jwsTyped = request,
            verified = false,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded =
            joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(walletRequest)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded =
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(encoded)

        decoded shouldBe walletRequest
    }

    test("openid4vp multisigned request round-trips") {
        val requestElement: JwsFlattened = testSignedOpenId4VpRequest.data.request.toJwsFlattened()
        val request: JwsGeneralTyped<AuthenticationRequestParameters> =
            (0..5).map { requestElement }.toJwsGeneral().typed()
        val walletRequest = RequestParametersFrom.OpenId4VpMultiSigned(
            jwsTyped = request,
            verified = false,
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded =
            joseCompliantSerializer.encodeToString<RequestParametersFrom<AuthenticationRequestParameters>>(walletRequest)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        // The protocol discriminator must be the spec-defined string, not the auto-generated class name,
        // so that external DC API payloads (from browsers/platform) with "protocol":"openid4vp-v1-multisigned"
        // are correctly decoded.
        encoded.shouldContain("\"protocol\":\"openid4vp-v1-multisigned\"")
        val decoded =
            joseCompliantSerializer.decodeFromString<RequestParametersFrom<AuthenticationRequestParameters>>(encoded)

        decoded shouldBe walletRequest
    }

    test("openid4vp multisigned request can be decoded from external dc api discriminator value") {
        val requestElement: JwsFlattened = testSignedOpenId4VpRequest.data.request.toJwsFlattened()
        val request: JwsGeneralTyped<AuthenticationRequestParameters> = listOf(requestElement).toJwsGeneral().typed()
        val walletRequest = DCAPIWalletRequest.OpenId4VpMultiSigned(
            request = OpenId4VpRequest.JwsGeneral(request),
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        // Encode, then tamper the protocol value to simulate what a real DC API platform payload looks like:
        // verify the decoder can find the class via the spec-defined discriminator string.
        val canonical = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(walletRequest)
        // After the @SerialName fix the canonical form already contains the correct value, so decoding it
        // is equivalent to decoding a real platform payload.
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(canonical)
        decoded.shouldBeInstanceOf<DCAPIWalletRequest.OpenId4VpMultiSigned>()
    }

        test("iso mdoc request round-trips") {
        val request = RequestParametersFrom.IsoMdoc(
            parameters = RequestParametersFrom.IsoMdoc.IsoMdocRequestWrapper(testIsoMdocRequest.data),
            jsonString = joseCompliantSerializer.encodeToString(testIsoMdocRequest.data),
            credentialIds = listOf("044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4"),
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<IsoMdocRequestParametersFrom>(request)
        encoded.shouldContain("\"credentialIds\"")
        encoded.shouldNotContain("\"credentialId\"")
        val decoded = joseCompliantSerializer.decodeFromString<IsoMdocRequestParametersFrom>(encoded)

        decoded shouldBe request
    }
}
