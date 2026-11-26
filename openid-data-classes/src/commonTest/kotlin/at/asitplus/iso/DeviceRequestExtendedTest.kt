package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.CoseEllipticCurve
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.CoseKeyParams
import at.asitplus.signum.indispensable.cosef.CoseKeyType
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.github.z4kn4fein.semver.Version
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/** The extended request of ISO/IEC DIS 18013-5:2026, D.4.1.3, as given there, including its `family._name`. */
private val extendedRequestExample = """
        A36776657273696F6E63312E316B646F63526571756573747383A16C6974656D7352657175657374D8185902B2A367646F635479
        7065756F72672E69736F2E31383031332E352E312E6D444C6A6E616D65537061636573A2716F72672E69736F2E31383031332E35
        2E31A768706F727472616974F56A62697274685F64617465F56A69737375655F64617465F56B6578706972795F64617465F56F64
        6F63756D656E745F6E756D626572F5781D676976656E5F6E616D655F6E6174696F6E616C5F636861726163746572F5781E66616D
        696C795F6E616D655F6E6174696F6E616C5F636861726163746572F5776F72672E69736F2E31383031332E352E312E61616D7661
        A1781B646F6D65737469635F64726976696E675F70726976696C65676573F56B72657175657374496E666FA274756E6971756544
        6F635365745265717569726564F577616C7465726E617469766544617461456C656D656E747383A270726571756573746564456C
        656D656E7482716F72672E69736F2E31383031332E352E31781D676976656E5F6E616D655F6E6174696F6E616C5F636861726163
        74657276616C7465726E6174697665456C656D656E7453657473818182716F72672E69736F2E31383031332E352E316A67697665
        6E5F6E616D65A270726571756573746564456C656D656E7482716F72672E69736F2E31383031332E352E31781E66616D696C795F
        6E616D655F6E6174696F6E616C5F63686172616374657276616C7465726E6174697665456C656D656E7453657473818182716F72
        672E69736F2E31383031332E352E316C66616D696C792E5F6E616D65A270726571756573746564456C656D656E7482776F72672E
        69736F2E31383031332E352E312E61616D7661781B646F6D65737469635F64726976696E675F70726976696C6567657376616C74
        65726E6174697665456C656D656E7453657473818182716F72672E69736F2E31383031332E352E317264726976696E675F707269
        76696C65676573A16C6974656D7352657175657374D818590204A367646F6354797065756F72672E69736F2E31383031332E352E
        312E6D444C6A6E616D65537061636573A1716F72672E69736F2E31383031332E352E31A568706F727472616974F56A676976656E
        5F6E616D65F56B6167655F6F7665725F3138F56B66616D696C795F6E616D65F5747265736964656E745F706F7374616C5F636F64
        65F56B72657175657374496E666FA274756E69717565446F635365745265717569726564F577616C7465726E6174697665446174
        61456C656D656E747382A270726571756573746564456C656D656E7482716F72672E69736F2E31383031332E352E316B6167655F
        6F7665725F313876616C7465726E6174697665456C656D656E7453657473828182716F72672E69736F2E31383031332E352E316C
        6167655F696E5F79656172738182716F72672E69736F2E31383031332E352E316A62697274685F64617465A27072657175657374
        6564456C656D656E7482716F72672E69736F2E31383031332E352E31747265736964656E745F706F7374616C5F636F646576616C
        7465726E6174697665456C656D656E7453657473828282716F72672E69736F2E31383031332E352E316D7265736964656E745F63
        69747982716F72672E69736F2E31383031332E352E316E7265736964656E745F73746174658182716F72672E69736F2E31383031
        332E352E31707265736964656E745F61646472657373A16C6974656D7352657175657374D81859040DA367646F6354797065756F
        72672E69736F2E32333232302E70686F746F49446A6E616D65537061636573A16F6F72672E69736F2E32333232302E31A668706F
        727472616974F5696C6173745F6E616D65F56A66697273745F6E616D65F56B6167655F6F7665725F3138F56D7265736964656E74
        5F63697479F56E7265736964656E745F7374617465F56B72657175657374496E666FA274756E69717565446F6353657452657175
        69726564F577616C7465726E617469766544617461456C656D656E747386A270726571756573746564456C656D656E74826F6F72
        672E69736F2E32333232302E316A66697273745F6E616D6576616C7465726E6174697665456C656D656E74536574738281826F6F
        72672E69736F2E32333232302E317166697273745F6E616D655F6C6174696E318182781A6F72672E69736F2E32333232302E6461
        746167726F7570732E3163646731A270726571756573746564456C656D656E74826F6F72672E69736F2E32333232302E31696C61
        73745F6E616D6576616C7465726E6174697665456C656D656E74536574738281826F6F72672E69736F2E32333232302E31706C61
        73745F6E616D655F6C6174696E318182781A6F72672E69736F2E32333232302E6461746167726F7570732E3163646731A2707265
        71756573746564456C656D656E74826F6F72672E69736F2E32333232302E3168706F72747261697476616C7465726E6174697665
        456C656D656E7453657473818182781A6F72672E69736F2E32333232302E6461746167726F7570732E3163646732A27072657175
        6573746564456C656D656E74826F6F72672E69736F2E32333232302E316D7265736964656E745F6369747976616C7465726E6174
        697665456C656D656E74536574738281826F6F72672E69736F2E32333232302E31747265736964656E745F706F7374616C5F636F
        646581826F6F72672E69736F2E32333232302E31707265736964656E745F61646472657373A270726571756573746564456C656D
        656E74826F6F72672E69736F2E32333232302E316E7265736964656E745F737461746576616C7465726E6174697665456C656D65
        6E74536574738281826F6F72672E69736F2E32333232302E31747265736964656E745F706F7374616C5F636F646581826F6F7267
        2E69736F2E32333232302E31707265736964656E745F61646472657373A270726571756573746564456C656D656E74826F6F7267
        2E69736F2E32333232302E316B6167655F6F7665725F313876616C7465726E6174697665456C656D656E74536574738381826F6F
        72672E69736F2E32333232302E316C6167655F696E5F796561727381826F6F72672E69736F2E32333232302E316A62697274685F
        646174658182781A6F72672E69736F2E32333232302E6461746167726F7570732E31636467317164657669636552657175657374
        496E666FD8185887A168757365436173657382A3696D616E6461746F7279F46C646F63756D656E74536574738181006C70757270
        6F736548696E7473A1716F72672E69736F2E6A7463312E7363313702A3696D616E6461746F7279F46C646F63756D656E74536574
        7382810181026C707572706F736548696E7473A1716F72672E69736F2E6A7463312E7363313701
""".filterNot { it.isWhitespace() }.decodeToByteArray(Base16Strict)

private const val MDL_NAMESPACE = "org.iso.18013.5.1"

private fun itemsRequest(
    vararg dataElements: String,
    requestInfo: DocRequestInfo? = null,
) = ItemsRequest(
    docType = "org.iso.18013.5.1.mDL",
    namespaces = mapOf(MDL_NAMESPACE to ItemsRequestList(dataElements.map { SingleItemsRequest(it, false) })),
    requestInfo = requestInfo,
)

private fun docRequest(vararg dataElements: String) = DocRequest(ByteStringWrapper(itemsRequest(*dataElements)))

private fun mdlElement(name: String) = ElementReference(MDL_NAMESPACE, name)

private fun deviceRequestInfo(vararg useCases: UseCase) = ByteStringWrapper(DeviceRequestInfo(useCases.toList()))

/** A construction that the CDDL of ISO/IEC DIS 18013-5:2026 does not allow. */
private data class Violation(val name: String, val construct: () -> Any)

val DeviceRequestExtendedTest by matrixSuite {

    "decodes the extended request example of ISO/IEC DIS 18013-5:2026, D.4.1.3" {
        val encoded = extendedRequestExample

        val decoded = coseCompliantSerializer.decodeFromByteArray<DeviceRequest>(encoded)

        decoded.apply {
            parsedVersion shouldBe IsoConstants.VERSION_1_1
            docRequests.size shouldBe 3
            docRequests[1].itemsRequest.value.requestInfo.shouldNotBeNull().apply {
                uniqueDocSetRequired shouldBe true
                alternativeDataElements.shouldNotBeNull().first() shouldBe AlternativeDataElementsSet(
                    requestedElement = mdlElement("age_over_18"),
                    alternativeElementSets = listOf(
                        listOf(mdlElement("age_in_years")),
                        listOf(mdlElement("birth_date")),
                    ),
                )
            }
            deviceRequestInfo.shouldNotBeNull().value.useCases shouldBe listOf(
                UseCase(
                    mandatory = false,
                    documentSets = listOf(listOf(0u)),
                    purposeHints = mapOf(
                        UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_DRIVING_PRIVILEGE_VERIFICATION
                    ),
                ),
                UseCase(
                    mandatory = false,
                    documentSets = listOf(listOf(1u), listOf(2u)),
                    purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_IDENTITY_VERIFICATION),
                ),
            )
        }
    }

    "encodes the decoded example of ISO/IEC DIS 18013-5:2026, D.4.1.3 to the same bytes" {
        val decoded = coseCompliantSerializer.decodeFromByteArray<DeviceRequest>(extendedRequestExample)

        val encoded = coseCompliantSerializer.encodeToByteArray(decoded)

        encoded shouldBe extendedRequestExample
    }

    "encodes docResponseEncryption as EncryptionParametersBytes, a tag-24 byte string" {
        val parameters = EncryptionParameters(
            recipientPublicKey = CoseKey(
                type = CoseKeyType.EC2,
                keyParams = CoseKeyParams.EcYBoolParams(curve = CoseEllipticCurve.P256),
            )
        )
        val requestInfo = DocRequestInfo(docResponseEncryption = ByteStringWrapper(parameters))
        // {"docResponseEncryption": #6.24(bstr .cbor EncryptionParameters)}
        val expected = byteArrayOf(0xA1.toByte()) +
                coseCompliantSerializer.encodeToByteArray("docResponseEncryption") +
                byteArrayOf(0xD8.toByte(), 0x18) +
                coseCompliantSerializer.encodeToByteArray(
                    ByteArraySerializer(),
                    coseCompliantSerializer.encodeToByteArray(parameters),
                )

        val encoded = coseCompliantSerializer.encodeToByteArray(requestInfo)

        encoded shouldBe expected
        coseCompliantSerializer.decodeFromByteArray<DocRequestInfo>(encoded) shouldBe requestInfo
    }

    "rejects what the CDDL of ISO/IEC DIS 18013-5:2026, 10.2 does not allow" - {
        listOf(
            Violation("no document request") {
                DeviceRequest(IsoConstants.VERSION_1_0, arrayOf())
            },
            Violation("empty readerAuthAll") {
                DeviceRequest(
                    parsedVersion = IsoConstants.VERSION_1_1,
                    docRequests = arrayOf(docRequest("age_over_18")),
                    readerAuthAll = arrayOf(),
                )
            },
            Violation("deviceRequestInfo in version 1.0") {
                DeviceRequest(
                    parsedVersion = Version(1, 0),
                    docRequests = arrayOf(docRequest("age_over_18")),
                    deviceRequestInfo = deviceRequestInfo(UseCase(true, listOf(listOf(0u)))),
                )
            },
            Violation("use case referencing a missing document request") {
                DeviceRequest(
                    parsedVersion = IsoConstants.VERSION_1_1,
                    docRequests = arrayOf(docRequest("age_over_18")),
                    deviceRequestInfo = deviceRequestInfo(UseCase(true, listOf(listOf(0u, 1u)))),
                )
            },
            Violation("empty useCases") { DeviceRequestInfo(listOf()) },
            Violation("use case without document set") { UseCase(true, listOf()) },
            Violation("empty document set") { UseCase(true, listOf(listOf())) },
            Violation("empty purposeHints") { UseCase(true, listOf(listOf(0u)), mapOf()) },
            Violation("empty alternativeDataElements") { DocRequestInfo(alternativeDataElements = listOf()) },
            Violation("empty issuerIdentifiers") { DocRequestInfo(issuerIdentifiers = listOf()) },
            Violation("no alternative element set") {
                AlternativeDataElementsSet(mdlElement("age_over_18"), listOf())
            },
            Violation("empty alternative element set") {
                AlternativeDataElementsSet(mdlElement("age_over_18"), listOf(listOf()))
            },
            Violation("alternatives for a data element that is not requested") {
                itemsRequest(
                    "birth_date",
                    requestInfo = DocRequestInfo(
                        alternativeDataElements = listOf(
                            AlternativeDataElementsSet(
                                requestedElement = mdlElement("age_over_18"),
                                alternativeElementSets = listOf(listOf(mdlElement("birth_date"))),
                            )
                        )
                    ),
                )
            },
            Violation("no requested name space") {
                ItemsRequest(docType = "org.iso.18013.5.1.mDL", namespaces = mapOf())
            },
            Violation("name space without data element") { ItemsRequestList(listOf()) },
        ).asData(nameFn = { it.name }) test { violation ->
            shouldThrow<IllegalArgumentException> { violation.construct() }
        }
    }
}
