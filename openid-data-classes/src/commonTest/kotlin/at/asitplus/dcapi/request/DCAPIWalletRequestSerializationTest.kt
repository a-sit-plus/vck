package at.asitplus.dcapi.request

import at.asitplus.dcapi.request.verifier.testIsoMdocRequest
import at.asitplus.dcapi.request.verifier.testSignedOpenId4VpRequest
import at.asitplus.dcapi.request.verifier.testUnsignedOpenId4VpRequest
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val DCAPIWalletRequestSerializationTest by testSuite {
    test("openid4vp unsigned request round-trips") {
        val request = DCAPIWalletRequest.OpenId4VpUnsigned(
            request = testUnsignedOpenId4VpRequest.request,
            credentialId = "044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4",
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(request)
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe request
    }

    test("openid4vp signed request round-trips") {
        val request = testSignedOpenId4VpRequest.request
        val walletRequest = DCAPIWalletRequest.OpenId4VpSigned(
            request = request,
            credentialId = "044c78be429198ffc2a66d935ff86e4e2bdb8ca2ab0cd1bacc85f3a73d8347b4",
            callingPackageName = "com.android.chrome",
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(walletRequest)
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe walletRequest
    }

    test("iso mdoc request round-trips") {
        val request = DCAPIWalletRequest.IsoMdoc(
            isoMdocRequest = testIsoMdocRequest.request,
            callingOrigin = "https://wallet.a-sit.at"
        )

        val encoded = joseCompliantSerializer.encodeToString<DCAPIWalletRequest>(request)
        val decoded = joseCompliantSerializer.decodeFromString<DCAPIWalletRequest>(encoded)

        decoded shouldBe request
    }
}
