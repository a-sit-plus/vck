package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Instant

val TokenIntrospectionSerializationTest by matrixSuite {

    testSuite("aud as string or array (RFC 7519 4.1.3)") {
        mapOf(
            """{"active":true,"aud":"https://rs.example.com"}""" to setOf("https://rs.example.com"),
            """{"active":true,"aud":["https://rs.example.com"]}""" to setOf("https://rs.example.com"),
            """{"active":true,"aud":["https://rs.example.com","https://other.example.com"]}""" to
                    setOf("https://rs.example.com", "https://other.example.com"),
        ).entries.asData(nameFn = { it.key }) test { (json, audience) ->
            joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(json).audience shouldBe audience
        }
    }

    test("one audience is encoded as string, several as array") {
        joseCompliantSerializer.encodeToString(
            TokenIntrospectionResponse(active = true, audience = setOf("https://rs.example.com"))
        ) shouldBe """{"active":true,"aud":"https://rs.example.com"}"""
        joseCompliantSerializer.encodeToString(
            TokenIntrospectionResponse(active = true, audience = setOf("https://a.example.com", "https://b.example.com"))
        ) shouldBe """{"active":true,"aud":["https://a.example.com","https://b.example.com"]}"""
    }

    test("JWT payload round trip with the claims of RFC 9701 5.") {
        val payload = TokenIntrospectionJwtPayload(
            issuer = "https://as.example.com/",
            audience = setOf("https://rs.example.com/resource"),
            issuedAt = Instant.fromEpochSeconds(1514797892),
            tokenIntrospection = TokenIntrospectionResponse(active = true, scope = "read write dolphin"),
        )
        val json = """{"iss":"https://as.example.com/","aud":"https://rs.example.com/resource",""" +
                """"iat":1514797892,"token_introspection":{"active":true,"scope":"read write dolphin"}}"""

        joseCompliantSerializer.encodeToString(payload) shouldBe json
        joseCompliantSerializer.decodeFromString<TokenIntrospectionJwtPayload>(json) shouldBe payload
    }
}
