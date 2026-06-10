package at.asitplus.rfc3986uri

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import io.ktor.http.Url

@Suppress("unused")
val Rfc3986PercentEncodingAwareStringTest by matrixSuite {
    testSuite("percent decoding equality") {
        (mapOf( // upper/lowercase
                "aaaaaaaaAAAAAAAA" to "aaaAAaAAaaaAAaAA"
            ).mapValues {
                it.key.chunked(2).joinToString("") {
                    "%$it"
                } to it.value.chunked(2).joinToString("") {
                    "%$it"
                }
            } + mapOf( // unreserved characters
                "~" to "%7E",
                "-" to "%2D",
                "." to "%2E",
                "_" to "%5F",
            ).mapValues {
                it.key to it.value
            } + ('0'..'9').plus('a'..'z').plus('A'..'Z').associate {
                it.toString() to (it.toString() to "%${it.code.toString(16)}")
            }).values.asData() test {
            Rfc3986UriQuery(it.first) shouldBe Rfc3986UriQuery(it.second)
        }
    }
    testSuite("case insensitivity") {
        mapOf(
                "%C3%A4" to "ä",
                "%C3%B6" to "ö",
                "%C3%BC" to "ü",
                "%C3%9F" to "ß",
                "%C3%A9" to "é",
                "%E2%82%AC" to "€",
                "%C2%A3" to "£",
                "%C2%A5" to "¥",
            ).asData() test { (encoded, decoded) ->
            Rfc3986PercentEncodingAwareString(encoded).decode() shouldBe decoded
        }
    }
}
