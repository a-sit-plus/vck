package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
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

    test("DPoP binding in cnf (RFC 9449 6.2)") {
        val json = """{"active":true,"sub":"someone@example.com","iss":"https://server.example.com",""" +
                """"nbf":1562262611,"exp":1562266216,"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}"""

        joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(json)
            .confirmationClaim?.jsonWebKeyThumbprint shouldBe "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
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

    test("response without service-specific members encodes as before") {
        val response = TokenIntrospectionResponse(active = true, scope = "read", subject = "someone@example.com")
        val json = """{"active":true,"scope":"read","sub":"someone@example.com"}"""

        joseCompliantSerializer.encodeToString(response) shouldBe json
        joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(json).also {
            it shouldBe response
            it.additionalClaims.shouldBeNull()
        }
    }

    test("service-specific members as top-level members (RFC 7662 2.2)") {
        val json = """{"active":true,"sub":"someone@example.com","given_name":"Susan",""" +
                """"address":{"locality":"Graz","country":"AT"},"nationalities":["AT","DE"]}"""

        val parsed = joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(json)

        parsed.subject shouldBe "someone@example.com"
        parsed.additionalClaims shouldBe Json.parseToJsonElement(
            """{"given_name":"Susan","address":{"locality":"Graz","country":"AT"},"nationalities":["AT","DE"]}"""
        ).jsonObject
        joseCompliantSerializer.encodeToString(parsed) shouldBe json
    }

    test("member with the internal name of additionalClaims stays a top-level member") {
        val json = """{"active":true,"additional_claims":"value","given_name":"Susan"}"""

        val parsed = joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(json)

        parsed.additionalClaims shouldBe Json.parseToJsonElement(
            """{"additional_claims":"value","given_name":"Susan"}"""
        ).jsonObject
        joseCompliantSerializer.encodeToString(parsed) shouldBe json
    }

    test("property wins over a service-specific member of the same name") {
        val response = TokenIntrospectionResponse(
            active = true,
            additionalClaims = Json.parseToJsonElement(
                """{"active":false,"sub":"someone-else@example.com","given_name":"Susan"}"""
            ).jsonObject,
        )

        joseCompliantSerializer.encodeToString(response) shouldBe """{"active":true,"given_name":"Susan"}"""
    }

    test("service-specific members parse without ignoreUnknownKeys") {
        Json.decodeFromString<TokenIntrospectionResponse>("""{"active":true,"given_name":"Susan"}""")
            .additionalClaims?.get("given_name") shouldBe JsonPrimitive("Susan")
    }

    test("JWT payload round trip keeps service-specific members") {
        val payload = TokenIntrospectionJwtPayload(
            issuer = "https://as.example.com/",
            audience = setOf("https://rs.example.com/resource"),
            issuedAt = Instant.fromEpochSeconds(1514797892),
            tokenIntrospection = TokenIntrospectionResponse(
                active = true,
                subject = "someone@example.com",
                additionalClaims = Json.parseToJsonElement("""{"given_name":"Susan"}""").jsonObject,
            ),
        )
        val json = """{"iss":"https://as.example.com/","aud":"https://rs.example.com/resource",""" +
                """"iat":1514797892,"token_introspection":{"active":true,"sub":"someone@example.com",""" +
                """"given_name":"Susan"}}"""

        joseCompliantSerializer.encodeToString(payload) shouldBe json
        joseCompliantSerializer.decodeFromString<TokenIntrospectionJwtPayload>(json) shouldBe payload
    }
}
