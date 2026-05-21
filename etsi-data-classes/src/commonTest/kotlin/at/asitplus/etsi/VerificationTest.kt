package at.asitplus.etsi

import at.asitplus.etsi.verification.TrustListLoader
import de.infix.testBalloon.framework.core.testSuite
import io.matthewnelson.encoding.base64.Base64

val VerificationTest by testSuite {


    test("test deserialization") {
        val loader = TrustListLoader()

        val list = loader.fetchTrustList()
        println(list)
    }
}