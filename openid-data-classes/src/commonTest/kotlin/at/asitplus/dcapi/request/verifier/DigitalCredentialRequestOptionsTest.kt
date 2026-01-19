package at.asitplus.dcapi.request.verifier

import at.asitplus.openid.JarRequestParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val DigitalCredentialRequestOptionsTest by testSuite {

    test("decode signed openid4vp request options") {
        val requestJwt = Json.parseToJsonElement(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON)
            .jsonObject["requests"].shouldNotBeNull()
            .jsonArray[0]
            .jsonObject["data"].shouldNotBeNull()
            .jsonObject["request"].shouldNotBeNull()
            .jsonPrimitive
            .content

        val decoded = joseCompliantSerializer
            .decodeFromString<DigitalCredentialRequestOptions>(DIGITAL_CREDENTIAL_REQUEST_OPTIONS_JSON)
        decoded.requests.size shouldBe 2
        val request = decoded.requests.first()
            .shouldBeInstanceOf<DigitalCredentialGetRequest.OpenId4VpSigned>()

        val jarRequest = request.request.shouldBeInstanceOf<JarRequestParameters>()
        jarRequest.request shouldBe requestJwt
    }
}
