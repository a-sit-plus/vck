package at.asitplus.rfc3986uri

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val Rfc3986UniformResourceIdentifierTest by matrixSuite {
    testSuite("parsing success") {
        mapOf(
            "https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html#claim-metadata" to listOf(
                "https",
                "www.ietf.org",
                "/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html",
                null,
                "claim-metadata",
            ),
            "https://user:password@www.ietf.org:8080?name=draft#claim-metadata" to listOf(
                "https",
                "user:password@www.ietf.org:8080",
                "",
                "name=draft",
                "claim-metadata",
            ),
            "https://user:password@127.0.0.1:8080?name=draft#claim-metadata" to listOf(
                "https",
                "user:password@127.0.0.1:8080",
                "",
                "name=draft",
                "claim-metadata",
            ),
            "https://user:password@[aaAA::]:8080?name=draft#claim-metadata" to listOf(
                "https",
                "user:password@[aaAA::]:8080",
                "",
                "name=draft",
                "claim-metadata",
            ),
            "http://a/b/c/d;p?q" to listOf(
                "http",
                "a",
                "/b/c/d;p",
                "q",
                null,
            ),
            "http://www.ics.uci.edu/pub/ietf/uri/#Related" to listOf(
                "http",
                "www.ics.uci.edu",
                "/pub/ietf/uri/",
                null,
                "Related",
            ),
            "http://www.w3.org/Addressing/" to listOf(
                "http",
                "www.w3.org",
                "/Addressing/",
                null,
                null,
            ),
            "ftp://foo.example.com/rfc/" to listOf(
                "ftp",
                "foo.example.com",
                "/rfc/",
                null,
                null,
            ),
            "http://www.ics.uci.edu/pub/ietf/uri/historical.html#WARNING" to listOf(
                "http",
                "www.ics.uci.edu",
                "/pub/ietf/uri/historical.html",
                null,
                "WARNING",
            ),
            "ftp://ftp.is.co.za/rfc/rfc1808.txt" to listOf(
                "ftp",
                "ftp.is.co.za",
                "/rfc/rfc1808.txt",
                null,
                null,
            ),
            "http://www.ietf.org/rfc/rfc2396.txt" to listOf(
                "http",
                "www.ietf.org",
                "/rfc/rfc2396.txt",
                null,
                null,
            ),
            "ldap://[2001:db8::7]/c=GB?objectClass?one" to listOf(
                "ldap",
                "[2001:db8::7]",
                "/c=GB",
                "objectClass?one",
                null,
            ),
            "mailto:John.Doe@example.com" to listOf(
                "mailto",
                null,
                "John.Doe@example.com",
                null,
                null,
            ),
            "news:comp.infosystems.www.servers.unix" to listOf(
                "news",
                null,
                "comp.infosystems.www.servers.unix",
                null,
                null,
            ),
            "tel:+1-816-555-1212" to listOf(
                "tel",
                null,
                "+1-816-555-1212",
                null,
                null,
            ),
            "telnet://192.0.2.16:80/" to listOf(
                "telnet",
                "192.0.2.16:80",
                "/",
                null,
                null,
            ),
            "urn:oasis:names:specification:docbook:dtd:xml:4.1.2" to listOf(
                "urn",
                null,
                "oasis:names:specification:docbook:dtd:xml:4.1.2",
                null,
                null,
            ),
            "urn:oasis:names:specification/docbook:dtd:xml:4.1.2" to listOf(
                "urn",
                null,
                "oasis:names:specification/docbook:dtd:xml:4.1.2",
                null,
                null,
            ),
        ).asData(nameFn = { (uri, _) -> uri }) test { (uri, data) ->
            shouldNotThrowAny {
                Rfc3986UniformResourceIdentifier(uri).apply {
                    schemeName.toString() shouldBe data[0]
                    authority?.toString(true) shouldBe data[1]
                    path.toString() shouldBe data[2]
                    query?.toString() shouldBe data[3]
                    fragment?.toString() shouldBe data[4]
                }
            }
        }
    }

    testSuite("path equality") {
        test("equal paths compare equal") {
            val a = Rfc3986UniformResourceIdentifier("http://example.com/a/b")
            val b = Rfc3986UniformResourceIdentifier("http://example.com/a/b")
            (a.path == b.path) shouldBe true
            a.path shouldBe b.path
        }
        test("different paths compare unequal") {
            val a = Rfc3986UniformResourceIdentifier("http://example.com/a")
            val b = Rfc3986UniformResourceIdentifier("http://example.com/b")
            (a.path == b.path) shouldBe false
            a.path.shouldNotBe(b.path)
        }
        test("non-empty path does not equal empty path") {
            val nonEmpty = Rfc3986UniformResourceIdentifier("http://example.com/a")
            (nonEmpty.path == Rfc3986UriPathEmpty) shouldBe false
            nonEmpty.path.shouldNotBe(Rfc3986UriPathEmpty)
        }
    }

    testSuite("empty port is accepted") {
        test("URI with trailing colon parses without error") {
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://example.com:") }
        }
        test("empty port is treated as absent") {
            Rfc3986UniformResourceIdentifier("http://example.com:").apply {
                authority.shouldNotBeNull().apply {
                    rawPort shouldBe null
                    port shouldBe null
                    host shouldBe Rfc3986AuthorityHost("example.com")
                }
            }
        }
        test("port syntax preserves leading zeros and arbitrary length") {
            val port = "000184467440737095516160"
            Rfc3986UniformResourceIdentifier("http://example.com:$port").apply {
                authority.shouldNotBeNull().apply {
                    rawPort shouldBe port
                    toString() shouldBe "example.com:$port"
                }
            }
        }
    }

    testSuite("root-only absolute path") {
        test("path-absolute may be just a slash") {
            shouldNotThrowAny { Rfc3986UriPathAbsolute("/") }
        }
        test("URI with root-only path parses without error") {
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("foo:/") }
        }
        test("double-slash path-absolute is still rejected") {
            shouldThrow<IllegalArgumentException> { Rfc3986UriPathAbsolute("//") }
        }
    }

    testSuite("path-noscheme colon rules") {
        test("colon after first segment is accepted") {
            shouldNotThrowAny { Rfc3986UriPathNoScheme("a/b:c") }
            shouldNotThrowAny { Rfc3986UriPathNoScheme("a/b/c:d") }
        }
        test("colon in first segment is rejected") {
            shouldThrow<IllegalArgumentException> {
                Rfc3986UriPathNoScheme("a:b")
            }
            shouldThrow<IllegalArgumentException> {
                Rfc3986UriPathNoScheme("a:b/c")
            }
        }
    }

    testSuite("string round-trips") {
        listOf(
            "https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-16.html#claim-metadata",
            "http://a/b/c/d;p?q",
            "http://www.ics.uci.edu/pub/ietf/uri/#Related",
            "http://www.w3.org/Addressing/",
            "ftp://foo.example.com/rfc/",
            "ftp://ftp.is.co.za/rfc/rfc1808.txt",
            "http://www.ietf.org/rfc/rfc2396.txt",
            "mailto:John.Doe@example.com",
            "telnet://192.0.2.16:80/",
            "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
            "https://user:password@www.ietf.org:8080?name=draft#claim-metadata",
            "https://user:password@127.0.0.1:8080?name=draft#claim-metadata",
            "https://user:password@[aaAA::]:8080?name=draft#claim-metadata",
            "ldap://[2001:db8::7]/c=GB?objectClass?one",
        ).asData() test { uri ->
            Rfc3986UniformResourceIdentifier(uri).string shouldBe uri
        }
    }
}
