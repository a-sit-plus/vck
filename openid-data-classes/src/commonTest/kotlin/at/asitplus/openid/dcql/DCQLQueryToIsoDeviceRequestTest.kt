package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NullSegment
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private const val VCT = "urn:eudi:pid:1"

private fun sdJwtQuery(
    vararg claims: DCQLJsonClaimsQuery,
    vctValues: List<String> = listOf(VCT),
    claimSets: List<List<String>>? = null,
) = DCQLSdJwtCredentialQuery(
    id = DCQLCredentialQueryIdentifier("pid"),
    format = CredentialFormatEnum.DC_SD_JWT,
    meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues),
    claims = DCQLClaimsQueryList(claims.toList().toNonEmptyList()),
    claimSets = claimSets?.map { set -> set.map { DCQLClaimsQueryIdentifier(it) } }?.toNonEmptyList(),
)

private fun DCQLCredentialQuery.toDeviceRequest() =
    DCQLQuery(credentials = DCQLCredentialQueryList(nonEmptyListOf(this))).toIso180137AnnexCDeviceRequest()

val DCQLQueryToIsoDeviceRequestTest by matrixSuite {

    "an SD-JWT credential query becomes an SD-JWT document request of its vct with mapped claims" {
        val itemsRequest = sdJwtQuery(
            DCQLJsonClaimsQuery(id = DCQLClaimsQueryIdentifier("name"), path = DCQLClaimsPathPointer("given_name")),
            DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(NameSegment("nationalities"), NullSegment)),
        ).toDeviceRequest().docRequests.single().itemsRequest.value

        itemsRequest.docType shouldBe VCT
        itemsRequest.namespaces.keys shouldBe setOf(DocRequestInfo.SD_JWT_NAMESPACE)
        itemsRequest.namespaces.getValue(DocRequestInfo.SD_JWT_NAMESPACE).entries shouldBe listOf(
            SingleItemsRequest("name", false),
            SingleItemsRequest("claim_1", false),
        )
        itemsRequest.requestInfo.shouldNotBeNull().apply {
            docFormat shouldBe DocRequestInfo.DOC_FORMAT_SD_JWT
            dataElementIdentifierMapping shouldBe mapOf(
                "name" to DCQLClaimsPathPointer("given_name"),
                "claim_1" to DCQLClaimsPathPointer(NameSegment("nationalities"), NullSegment),
            )
        }
    }

    "claim_sets, claim values, several vcts, and clashing identifiers can not be expressed" {
        val given = DCQLJsonClaimsQuery(id = DCQLClaimsQueryIdentifier("a"), path = DCQLClaimsPathPointer("given_name"))
        val family = DCQLJsonClaimsQuery(id = DCQLClaimsQueryIdentifier("b"), path = DCQLClaimsPathPointer("family_name"))
        listOf(
            sdJwtQuery(given, family, claimSets = listOf(listOf("a"), listOf("b"))),
            sdJwtQuery(given.copy(values = listOf(DCQLExpectedClaimValue.StringValue("Erika")))),
            sdJwtQuery(given, vctValues = listOf(VCT, "urn:eudi:pid:at:1")),
            sdJwtQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("given_name")),
                DCQLJsonClaimsQuery(id = DCQLClaimsQueryIdentifier("claim_0"), path = DCQLClaimsPathPointer("x")),
            ),
        ).forEach { query ->
            shouldThrow<IllegalArgumentException> { query.toDeviceRequest() }
        }
    }
}
