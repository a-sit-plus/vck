package at.asitplus.etsi

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json
import kotlin.time.Instant

val EtsiModelConformanceTest by matrixSuite {
    test("a supply point need not specify a service type") {
        val wire = """{"uriValue":"https://example.org/service"}"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<ServiceSupplyPoint>(wire))) shouldBe
                Json.parseToJsonElement(wire)
    }
    test("a closed list has an explicit null next update") {
        val wire = """{"LoTEVersionIdentifier":1,"LoTESequenceNumber":1,"SchemeOperatorName":[{"lang":"en","value":"Operator"}],"ListIssueDateTime":"2026-01-01T00:00:00Z","NextUpdate":null}"""
        val info = Json.decodeFromString<ListAndSchemeInformation>(wire)
        Json.parseToJsonElement(Json.encodeToString(info)) shouldBe Json.parseToJsonElement(wire)
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<ListAndSchemeInformation>(wire.replace(",\"NextUpdate\":null", ""))
        }
    }
    test("digital identity uses the binding names and primitive identifier representations") {
        val wire = """{"X509SubjectNames":["CN=Example"],"X509SKIs":["AQID"],"OtherIds":["urn:example:service"],"PublicKeyValues":[{"kty":"RSA","n":"AQID","e":"AQAB"}]}"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<ServiceDigitalIdentity>(wire))) shouldBe
                Json.parseToJsonElement(wire)
    }
    listOf("{}", """{"X509Certificates":[null]}""", """{"X509Certificates":[],"OtherIds":["urn:example:service"]}""").asData() test { wire ->
        shouldThrow<IllegalArgumentException> { Json.decodeFromString<ServiceDigitalIdentity>(wire) }
    }
    test("one unparseable certificate does not prevent reading the other list entries") {
        val identity = Json.decodeFromString<ServiceDigitalIdentity>("""{"X509Certificates":[{"val":"not-a-certificate"}]}""")
        identity.x509Certificates shouldBe listOf(null)
        shouldThrow<IllegalArgumentException> { Json.encodeToString(identity) }
    }
    test("non-PKI service identifiers remain supported") {
        Json.decodeFromString<ServiceDigitalIdentity>("""{"OtherIds":["urn:example:service"]}""")
    }
    test("other-list pointers use nested qualifiers and plural digital identities") {
        val wire = """{"LoTELocation":"https://example.org/list","ServiceDigitalIdentities":[{"OtherIds":["urn:example:issuer"]}],"LoTEQualifiers":[{"LoTEType":"urn:example:lote","SchemeOperatorName":[{"lang":"en","value":"Operator"}],"MimeType":"application/json"}]}"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<OtherLoTEPointer>(wire))) shouldBe
                Json.parseToJsonElement(wire)
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<OtherLoTEPointer>(wire.replace(",\"MimeType\":\"application/json\"", ""))
        }
    }
    test("arbitrary service, entity and associated-body extensions retain their content") {
        val wire = """{"VendorExtension":{"enabled":true}}"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<ServiceInformationExtension>(wire))) shouldBe
                Json.parseToJsonElement(wire)
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<TEInformationExtension>(wire))) shouldBe
                Json.parseToJsonElement(wire)
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<AssociatedBodyInformationExtension>(wire))) shouldBe
                Json.parseToJsonElement(wire)
    }
    test("a legal notice is a plain string") {
        val wire = """[{"LoTELegalNotice":"Terms of use"}]"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<PolicyOrLegalNotice>(wire))) shouldBe
                Json.parseToJsonElement(wire)
    }
    listOf(
        "[{}]",
        """[{"LoTELegalNotice":"Notice","LoTEPolicy":{"lang":"en","uriValue":"https://example.org/policy"}}]""",
        """[{"LoTELegalNotice":"Notice"},{"LoTEPolicy":{"lang":"en","uriValue":"https://example.org/policy"}}]""",
    ).asData() test { wire ->
        shouldThrow<IllegalArgumentException> { Json.decodeFromString<PolicyOrLegalNotice>(wire) }
    }
    listOf<Pair<String, KSerializer<*>>>(
        "names" to SchemeOperatorName.serializer(),
        "entity names" to TEName.serializer(),
        "trade names" to TETradeName.serializer(),
        "scheme information" to SchemeInformationURI.serializer(),
        "scheme rules" to SchemeTypeCommunityRules.serializer(),
        "associated-body extensions" to AssociatedBodyInformationExtensions.serializer(),
        "scheme extensions" to SchemeExtensions.serializer(),
        "scheme names" to SchemeName.serializer(),
        "postal addresses" to PostalAddresses.serializer(),
        "services" to TrustedEntityServices.serializer(),
        "service names" to ServiceName.serializer(),
        "history" to ServiceHistory.serializer(),
        "other lists" to PointersToOtherLoTE.serializer(),
        "policies" to PolicyOrLegalNotice.serializer(),
        "service extensions" to ServiceInformationExtensions.serializer(),
    ).asData(nameFn = { it.first }) test { (_, serializer) ->
        shouldThrow<IllegalArgumentException> { Json.decodeFromString(serializer, "[]") }
    }
    test("scheme operator contacts require a website as well as email") {
        val emailOnly = """[{"lang":"en","uriValue":"mailto:support@example.org"}]"""
        shouldThrow<IllegalArgumentException> { Json.decodeFromString<ElectronicAddress>(emailOnly) }
        val contacts = emailOnly.dropLast(1) + """,{"lang":"en","uriValue":"http://example.org/support"}]"""
        Json.decodeFromString<ElectronicAddress>(contacts)
        Json.decodeFromString<TEElectronicAddress>(contacts)
    }
    test("trusted entity contacts accept email without a website") {
        val wire = """[{"lang":"en","uriValue":"mailto:support@example.org"}]"""
        Json.parseToJsonElement(Json.encodeToString(Json.decodeFromString<TEElectronicAddress>(wire))) shouldBe
                Json.parseToJsonElement(wire)
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString<TEElectronicAddress>("""[{"lang":"en","uriValue":"https://example.org/support"}]""")
        }
    }
    test("ListAndSchemeInformation and the list envelope keep their existing optionality") {
        Json.decodeFromString<ListOfTrustedEntities>("{}")
        Json.decodeFromString<ListAndSchemeInformation>(
            """{"LoTEVersionIdentifier":1,"LoTESequenceNumber":1,"SchemeOperatorName":[{"lang":"en","value":"Operator"}],"ListIssueDateTime":"2026-01-01T00:00:00Z","NextUpdate":"2026-02-01T00:00:00Z"}"""
        )
    }
    test("timestamps require a four-digit year on both read and write") {
        val instant = Instant.parse("+10000-01-01T00:00:00Z")
        shouldThrow<IllegalArgumentException> {
            Json.decodeFromString(EtsiInstantSerializer(), "\"$instant\"")
        }
        shouldThrow<IllegalArgumentException> { Json.encodeToString(EtsiInstantSerializer(), instant) }
    }
}
