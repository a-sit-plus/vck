package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UniformResourceIdentifier
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986UniformResourceIdentifierTest by testSuite {
    testSuite("parsing success") {
        withData(
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
            ).mapValues {
                it.key to it.value
            }
        ) { (uri, data) ->
            shouldNotThrowAny {
                val uri = Rfc3986UniformResourceIdentifier(uri)
                uri.schemeName.toString() shouldBe data[0]
                uri.authority?.toString(true) shouldBe data[1]
                uri.path.toString() shouldBe data[2]
                uri.query?.toString() shouldBe data[3]
                uri.fragment?.toString() shouldBe data[4]
            }
        }
    }
}
