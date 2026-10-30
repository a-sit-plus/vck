package at.asitplus.iso

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.IndexSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.github.z4kn4fein.semver.Version
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@OptIn(ExperimentalStdlibApi::class)
private fun String.cborText() = "${(0x60 + length).toString(16)}${encodeToByteArray().toHexString()}"

/** The SD-JWT DocRequest of the example of WG10 N2933 v2, "DeviceRequest changes", with array paths added. */
private val sdJwtItemsRequest = ItemsRequest(
    docType = "urn:eudi:pid:1",
    namespaces = mapOf(
        DocRequestInfo.SD_JWT_NAMESPACE to ItemsRequestList(
            listOf(
                SingleItemsRequest("sd_jwt_given_name", false),
                SingleItemsRequest("sd_jwt_postal_code", false),
                SingleItemsRequest("sd_jwt_nationalities", false),
            )
        )
    ),
    requestInfo = DocRequestInfo(
        docFormat = DocRequestInfo.DOC_FORMAT_SD_JWT,
        dataElementIdentifierMapping = mapOf(
            "sd_jwt_given_name" to DCQLClaimsPathPointer("given_name"),
            "sd_jwt_postal_code" to DCQLClaimsPathPointer("address", "postal_code"),
            "sd_jwt_locality" to DCQLClaimsPathPointer("address", "locality"),
            "sd_jwt_nationalities" to DCQLClaimsPathPointer(NameSegment("nationalities"), NullSegment),
            "sd_jwt_first_nationality" to DCQLClaimsPathPointer(NameSegment("nationalities"), IndexSegment(0U)),
        ),
        alternativeDataElements = listOf(
            AlternativeDataElementsSet(
                requestedElement = ElementReference(DocRequestInfo.SD_JWT_NAMESPACE, "sd_jwt_postal_code"),
                alternativeElementSets = listOf(
                    listOf(ElementReference(DocRequestInfo.SD_JWT_NAMESPACE, "sd_jwt_locality"))
                ),
            )
        ),
    ),
)

@OptIn(ExperimentalStdlibApi::class)
val SdJwtDocumentSerializationTest by matrixSuite {

    "an SD-JWT DocRequestInfo round-trips with text, unsigned integer, and null path components" {
        val encoded = coseCompliantSerializer.encodeToByteArray(sdJwtItemsRequest)

        coseCompliantSerializer.decodeFromByteArray<ItemsRequest>(encoded) shouldBe sdJwtItemsRequest
        val requestInfo = coseCompliantSerializer.decodeFromByteArray<ItemsRequest>(encoded).requestInfo!!
        requestInfo.isSdJwt shouldBe true
    }

    "path components are encoded as an array of text strings, unsigned integers, and null" {
        val hex = coseCompliantSerializer.encodeToByteArray(sdJwtItemsRequest).toHexString()

        // ["nationalities", null] and ["nationalities", 0]
        hex shouldContain "82${"nationalities".cborText()}f6"
        hex shouldContain "82${"nationalities".cborText()}00"
        hex shouldContain "dc+sd-jwt".cborText()
    }

    "a negative integer or an empty array is no path" {
        listOf(
            // {"docFormat": "dc+sd-jwt", "dataElementIdentifierMapping": {"a": [-1]}}
            "a2${"docFormat".cborText()}${"dc+sd-jwt".cborText()}" +
                    "${"dataElementIdentifierMapping".cborText()}a1${"a".cborText()}8120",
            // {"docFormat": "dc+sd-jwt", "dataElementIdentifierMapping": {"a": []}}
            "a2${"docFormat".cborText()}${"dc+sd-jwt".cborText()}" +
                    "${"dataElementIdentifierMapping".cborText()}a1${"a".cborText()}80",
        ).forEach { hex ->
            shouldThrowAny { coseCompliantSerializer.decodeFromByteArray<DocRequestInfo>(hex.hexToByteArray()) }
        }
    }

    "a DocRequestInfo without the fields of N2933 is encoded as before" {
        val hex = coseCompliantSerializer.encodeToByteArray(DocRequestInfo(uniqueDocSetRequired = true)).toHexString()

        hex shouldBe "a1${"uniqueDocSetRequired".cborText()}f5"
        hex shouldNotContain "docFormat".cborText()
    }

    "a DeviceResponse with other documents round-trips, one without is encoded as before" {
        val response = DeviceResponse(
            parsedVersion = Version(1, 0),
            status = 0U,
            otherDocuments = arrayOf(
                OtherDocument(DocRequestInfo.DOC_FORMAT_SD_JWT, byteArrayOf(0x78, 0x01, 0x02), listOf(0U, 2U))
            ),
        )
        val encoded = coseCompliantSerializer.encodeToByteArray(response)

        coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(encoded) shouldBe response
        encoded.toHexString() shouldContain "otherDocuments".cborText()
        coseCompliantSerializer.encodeToByteArray(DeviceResponse(Version(1, 0), status = 0U)).toHexString()
            .shouldNotContain("otherDocuments".cborText())
    }
}
