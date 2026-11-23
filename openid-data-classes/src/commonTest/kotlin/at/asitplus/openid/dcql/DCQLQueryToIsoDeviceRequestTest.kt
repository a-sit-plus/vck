package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ElementReference
import at.asitplus.iso.IsoConstants
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

val DCQLQueryToIsoDeviceRequestTest by matrixSuite {
    val namespace = "org.iso.18013.5.1"

    fun element(name: String, id: String? = null, values: List<DCQLExpectedClaimValue>? = null) =
        DCQLIsoMdocClaimsQuery(
            id = id?.let { DCQLClaimsQueryIdentifier(it) },
            values = values,
            path = DCQLClaimsPathPointer(namespace, name),
        )

    fun mdocQuery(
        id: String,
        vararg claims: DCQLIsoMdocClaimsQuery,
        claimSets: List<List<String>>? = null,
        multiple: Boolean = false,
        trustedAuthorities: List<DCQLTrustedAuthorityQueryEntry>? = null,
    ) = DCQLIsoMdocCredentialQuery(
        id = DCQLCredentialQueryIdentifier(id),
        meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(doctypeValue = "doctype.$id"),
        claims = DCQLClaimsQueryList(*claims),
        claimSets = claimSets?.map { set -> set.map { DCQLClaimsQueryIdentifier(it) } }
            ?.let { nonEmptyListOf(it.first(), *it.drop(1).toTypedArray()) },
        multiple = multiple,
        trustedAuthorities = trustedAuthorities?.let { nonEmptyListOf(it.first(), *it.drop(1).toTypedArray()) },
    )

    fun requiredSet(vararg ids: String) = DCQLCredentialSetQuery(
        options = nonEmptyListOf(ids.map { DCQLCredentialQueryIdentifier(it) }),
        required = true,
    )

    fun query(vararg credentials: DCQLCredentialQuery, credentialSets: List<DCQLCredentialSetQuery>? = null) =
        DCQLQuery(
            credentials = DCQLCredentialQueryList(credentials.first(), *credentials.drop(1).toTypedArray()),
            credentialSets = credentialSets?.let { nonEmptyListOf(it.first(), *it.drop(1).toTypedArray()) },
        )

    "converted" - {
        test("every credential query is a DocRequest with its data elements and intent to retain") {
            val elementPortrait = DCQLIsoMdocClaimsQuery(
                path = DCQLClaimsPathPointer(namespace, "portrait"),
                intentToRetain = true,
            )
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name"), elementPortrait),
                mdocQuery("pid", element("given_name")),
            )

            dcqlQuery.toIso180137AnnexCDeviceRequest().apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_0
                deviceRequestInfo shouldBe null
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf("doctype.mdl", "doctype.pid")
                docRequests.map { it.itemsRequest.value.requestInfo } shouldBe
                        listOf(DocRequestInfo(uniqueDocSetRequired = true), DocRequestInfo(uniqueDocSetRequired = true))
                docRequests.first().itemsRequest.value.namespaces shouldBe mapOf(
                    namespace to ItemsRequestList(
                        listOf(
                            SingleItemsRequest("family_name", false),
                            SingleItemsRequest("portrait", true)
                        )
                    )
                )
            }
        }

        test("credential sets requiring every credential query have no use cases") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                credentialSets = listOf(requiredSet("mdl"), requiredSet("pid")),
            )

            dcqlQuery.toIso180137AnnexCDeviceRequest().apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_0
                deviceRequestInfo shouldBe null
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf("doctype.mdl", "doctype.pid")
            }
        }

        test("alternative and optional credentials are use cases, in version 1.1") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                mdocQuery("photoid", element("portrait")),
                credentialSets = listOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(
                            listOf(DCQLCredentialQueryIdentifier("mdl")),
                            listOf(DCQLCredentialQueryIdentifier("pid")),
                        ),
                    ),
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(listOf(DCQLCredentialQueryIdentifier("photoid"))),
                        required = false,
                    ),
                ),
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_1
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf("doctype.mdl", "doctype.pid", "doctype.photoid")
                deviceRequestInfo.shouldNotBeNull().value.useCases shouldBe listOf(
                    UseCase(mandatory = true, documentSets = listOf(listOf(0u), listOf(1u))),
                    UseCase(mandatory = false, documentSets = listOf(listOf(2u))),
                )
            }
        }

        test("credential queries no credential set requests are left out") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                mdocQuery("photoid", element("portrait")),
                credentialSets = listOf(requiredSet("pid"), requiredSet("photoid")),
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_0
                deviceRequestInfo shouldBe null
                docRequests.map { it.itemsRequest.value.docType } shouldBe listOf("doctype.pid", "doctype.photoid")
            }
        }

        test("multiple credentials for one query are not a unique document set") {
            val dcqlQuery = query(mdocQuery("mdl", element("family_name"), multiple = true))

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.requestInfo shouldBe
                    DocRequestInfo(uniqueDocSetRequired = false)
        }

        test("trusted authorities of type aki are the issuer identifiers") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name"),
                    trustedAuthorities = listOf(
                        DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                            values = nonEmptyListOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y", "AQID")
                        ),
                        DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(values = nonEmptyListOf("AQID")),
                    ),
                )
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.requestInfo shouldBe DocRequestInfo(
                uniqueDocSetRequired = true,
                issuerIdentifiers = listOf(
                    "s9tIpPmhxdiuNkHMEWNpYim8S8Y".decodeToByteArray(Base64UrlStrict),
                    byteArrayOf(1, 2, 3),
                ),
            )
        }

        test("a single claim combination requests exactly the claims of that option") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name", id = "0"),
                    element("portrait", id = "1"),
                    element("given_name", id = "2"),
                    claimSets = listOf(listOf("0", "2")),
                )
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe mapOf(
                namespace to ItemsRequestList(
                    listOf(SingleItemsRequest("family_name", false), SingleItemsRequest("given_name", false))
                )
            )
        }

        test("of claim combinations, the one every other contains is requested, as for claims if available") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name", id = "0"),
                    element("portrait", id = "1"),
                    claimSets = listOf(listOf("0", "1"), listOf("0")),
                )
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe mapOf(
                namespace to ItemsRequestList(listOf(SingleItemsRequest("family_name", false)))
            )
        }

        test("alternative claim combinations are requested as alternative data elements") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name", id = "0"),
                    element("age_over_18", id = "1"),
                    element("birth_date", id = "2"),
                    claimSets = listOf(listOf("0", "1"), listOf("0", "2")),
                )
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.apply {
                namespaces shouldBe mapOf(
                    namespace to ItemsRequestList(
                        listOf(
                            SingleItemsRequest("family_name", false),
                            SingleItemsRequest("age_over_18", false)
                        )
                    )
                )
                requestInfo.shouldNotBeNull().alternativeDataElements shouldBe listOf(
                    AlternativeDataElementsSet(
                        requestedElement = ElementReference(namespace, "age_over_18"),
                        alternativeElementSets = listOf(listOf(ElementReference(namespace, "birth_date"))),
                    )
                )
            }
        }

        test("expected claim values of a data element that is not requested are not in the way") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name", id = "0"),
                    element("issuing_country", id = "1", values = listOf(DCQLExpectedClaimValue.StringValue("AT"))),
                    claimSets = listOf(listOf("0", "1"), listOf("0")),
                )
            )

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe mapOf(
                namespace to ItemsRequestList(listOf(SingleItemsRequest("family_name", false)))
            )
        }

        test("a data element queried twice is requested once, retained if any of its queries retains it") {
            val retained = DCQLIsoMdocClaimsQuery(
                path = DCQLClaimsPathPointer(namespace, "portrait"),
                intentToRetain = true,
            )
            val dcqlQuery = query(mdocQuery("mdl", element("portrait"), retained))

            val deviceRequest = dcqlQuery.toIso180137AnnexCDeviceRequest()

            deviceRequest.docRequests.single().itemsRequest.value.namespaces shouldBe mapOf(
                namespace to ItemsRequestList(listOf(SingleItemsRequest("portrait", true)))
            )
        }
    }

    "rejected instead of flattened" - {
        test("expected claim values of an alternative data element") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("age_over_18", id = "0"),
                    element("issuing_country", id = "1", values = listOf(DCQLExpectedClaimValue.StringValue("AT"))),
                    claimSets = listOf(listOf("0"), listOf("1")),
                )
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("alternative data elements retained differently than the one they are alternatives to") {
            val retained = DCQLIsoMdocClaimsQuery(
                id = DCQLClaimsQueryIdentifier("1"),
                path = DCQLClaimsPathPointer(namespace, "birth_date"),
                intentToRetain = true,
            )
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("age_over_18", id = "0"),
                    retained,
                    claimSets = listOf(listOf("0"), listOf("1")),
                )
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("claim combinations whose option contained in all others has no claim") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("portrait", id = "0"), claimSets = listOf(listOf("0"), listOf()))
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("a single claim combination without claims") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name", id = "0"), claimSets = listOf(listOf()))
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("expected claim values") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("issuing_country", values = listOf(DCQLExpectedClaimValue.StringValue("AT"))))
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("credential sets that are all optional") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                credentialSets = listOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(listOf(DCQLCredentialQueryIdentifier("mdl"))),
                        required = false,
                    )
                ),
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("trusted authorities of another type than aki") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name"),
                    trustedAuthorities = listOf(
                        DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                            values = nonEmptyListOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y")
                        ),
                        DCQLTrustedAuthorityQueryEntryETSITrustedList(
                            values = nonEmptyListOf("https://lotl.example.com")
                        ),
                    ),
                )
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }
    }
}
