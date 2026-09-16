package at.asitplus.openid

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.maps.shouldNotContainKey
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.ktor.http.Url
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException

/**
 * Pins the contract of the `application/x-www-form-urlencoded` (de)serialization in `FormUrlEncoding.kt`, which carries
 * OAuth 2.0, OpenID4VCI and OpenID4VP parameters in URL queries, URL fragments and POST bodies.
 */
val FormUrlEncodingTest by matrixSuite {

    // --- the mapping of members onto parameters ------------------------------------------------------------------

    test("primitive members encode unquoted, and decode back to their type") {
        val params = TestParameters(string = "foo", number = 42, flag = true).encodeToParameters()

        params shouldBe mapOf("string" to "foo", "number" to "42", "flag" to "true")
        params.decode<TestParameters>() shouldBe TestParameters(string = "foo", number = 42, flag = true)
    }

    test("object and array members encode as compact JSON, and decode back") {
        val input = TestParameters(nested = NestedObject(key = "a", count = 1), list = listOf("x", "y"))
        val params = input.encodeToParameters()

        params["nested"] shouldBe """{"key":"a","count":1}"""
        params["list"] shouldBe """["x","y"]"""
        params.decode<TestParameters>() shouldBe input
    }

    test("string members keep JSON content verbatim instead of parsing it") {
        // this is what `wallet_metadata` of `RequestObjectParameters` relies on
        val input = TestParameters(jsonString = """{"key":"a","count":1}""")

        input.encodeToParameters()["json_string"] shouldBe """{"key":"a","count":1}"""
        input.encodeToParameters().decode<TestParameters>() shouldBe input
    }

    test("wallet metadata survives a round-trip as a string") {
        val input = RequestObjectParameters(
            metadata = OAuth2AuthorizationServerMetadata(issuer = "https://wallet.example.com"),
            nonce = "nonce",
        )

        input.encodeToParameters().decode<RequestObjectParameters>().apply {
            walletMetadataString shouldBe input.walletMetadataString
            walletMetadata.shouldNotBeNull().issuer shouldBe "https://wallet.example.com"
            walletNonce shouldBe "nonce"
        }
    }

    test("unknown parameters are ignored") {
        mapOf("string" to "foo", "not_a_member" to "bar").decode<TestParameters>() shouldBe
                TestParameters(string = "foo")
    }

    test("null members are omitted") {
        TestParameters(string = "foo").encodeToParameters() shouldBe mapOf("string" to "foo")
    }

    test("an empty value is kept for a string member, but dropped for any other") {
        // a non-string member has no JSON literal to deserialize from an empty value
        mapOf("string" to "", "number" to "", "nested" to "").decode<TestParameters>() shouldBe
                TestParameters(string = "")
    }

    test("encoding a literal is not supported") {
        shouldThrow<SerializationException> { "not an object".encodeToParameters() }
    }

    test("a top-level array encodes to its indices") {
        listOf("a", "b").encodeToParameters() shouldBe mapOf("0" to "a", "1" to "b")
    }

    // --- the percent-encoded wire format -------------------------------------------------------------------------

    test("values that collide with the wire format survive a round-trip") {
        val input = TestParameters(string = "a&b=c+d e%f?g#h/i", jsonString = """{"ü":"ö"}""")

        input.encodeToFormUrlEncoded().decodeFromFormUrlEncoded<TestParameters>() shouldBe input
    }

    test("values are decoded exactly once") {
        // regression: decoding the parameters of an already-decoded `Url` mangled every value containing a percent sign
        Url("https://example.com/?string=a%2520b").decodeFromQuery<TestParameters>().string shouldBe "a%20b"
        Url("https://example.com/?string=a%20b").decodeFromQuery<TestParameters>().string shouldBe "a b"
    }

    test("a plus sign in a value means a space, and a literal plus sign is encoded") {
        "string=a+b".decodeFromFormUrlEncoded<TestParameters>().string shouldBe "a b"
        TestParameters(string = "a+b").encodeToFormUrlEncoded() shouldBe "string=a%2Bb"
    }

    test("names without a value are dropped") {
        "string=foo&flag&number=1".toFormParameters() shouldBe mapOf("string" to "foo", "number" to "1")
    }

    test("a repeated name collapses to its last value") {
        "string=first&string=last".decodeFromFormUrlEncoded<TestParameters>().string shouldBe "last"
    }

    test("an empty payload decodes to an object without members") {
        "".decodeFromFormUrlEncoded<TestParameters>() shouldBe TestParameters()
        "".toFormParameters() shouldBe emptyMap()
    }

    test("an authentication request survives a round-trip through a URL") {
        val input = AuthenticationRequestParameters(
            responseType = "code",
            clientId = "https://example.com/rp",
            redirectUrl = "https://example.com/cb?session=1",
            state = "ü&=+",
        )

        Url("https://wallet.example.com/authorize?${input.encodeToFormUrlEncoded()}")
            .decodeFromQuery<AuthenticationRequestParameters>() shouldBe input
    }

    // --- picking parameters off a URL ----------------------------------------------------------------------------

    test("parameters are read from the query, or from the fragment") {
        Url("https://example.com/cb?string=query").decodeFromQuery<TestParameters>().string shouldBe "query"
        Url("https://example.com/cb#string=fragment").decodeFromFragment<TestParameters>().string shouldBe "fragment"
    }

    test("the fragment takes precedence over the query") {
        Url("https://example.com/cb?string=query#string=fragment")
            .decodeFromFragmentOrQuery<TestParameters>().shouldNotBeNull().string shouldBe "fragment"
    }

    test("a URL carrying neither query nor fragment decodes to null") {
        // `ResponseParser` relies on this to tell a URL from a POST body, which `Url` parses as a path
        Url("https://example.com/cb").decodeFromFragmentOrQuery<TestParameters>().shouldBeNull()
        Url("string=foo&number=1").decodeFromFragmentOrQuery<TestParameters>().shouldBeNull()
    }

    test("the parts of a URL that are not parameters are not mistaken for one") {
        Url("https://example.com/cb?string=foo").decodeFromQuery<TestParameters>().string shouldBe "foo"
        Url("https://example.com/cb?string=foo").encodedQuery.toFormParameters() shouldNotContainKey
                "https://example.com/cb?string"
    }
}

@Serializable
data class TestParameters(
    @SerialName("string") val string: String? = null,
    @SerialName("number") val number: Int? = null,
    @SerialName("flag") val flag: Boolean? = null,
    @SerialName("nested") val nested: NestedObject? = null,
    @SerialName("list") val list: List<String>? = null,
    /** Declared as a string, so its content is kept verbatim even when it is JSON itself. */
    @SerialName("json_string") val jsonString: String? = null,
)

@Serializable
data class NestedObject(
    @SerialName("key") val key: String,
    @SerialName("count") val count: Int,
)
