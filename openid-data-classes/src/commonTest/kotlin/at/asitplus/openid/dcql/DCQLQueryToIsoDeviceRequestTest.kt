package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

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
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf("doctype.mdl", "doctype.pid")
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

        test("credential sets requiring every credential query are converted") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                credentialSets = listOf(requiredSet("mdl"), requiredSet("pid")),
            )

            dcqlQuery.toIso180137AnnexCDeviceRequest().apply {
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf("doctype.mdl", "doctype.pid")
            }
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
        test("alternative claim combinations, none contained in all others") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("age_over_18", id = "0"),
                    element("birth_date", id = "1"),
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

        test("alternative credentials") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                credentialSets = listOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(
                            listOf(DCQLCredentialQueryIdentifier("mdl")),
                            listOf(DCQLCredentialQueryIdentifier("pid")),
                        ),
                    )
                ),
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("optional credentials") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                credentialSets = listOf(
                    requiredSet("mdl"),
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(listOf(DCQLCredentialQueryIdentifier("pid"))),
                        required = false,
                    ),
                ),
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("credential queries no credential set requests") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("family_name")),
                mdocQuery("pid", element("given_name")),
                credentialSets = listOf(requiredSet("mdl")),
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("expected claim values") {
            val dcqlQuery = query(
                mdocQuery("mdl", element("issuing_country", values = listOf(DCQLExpectedClaimValue.StringValue("AT"))))
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("multiple credentials for one query") {
            val dcqlQuery = query(mdocQuery("mdl", element("family_name"), multiple = true))

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }

        test("trusted authorities") {
            val dcqlQuery = query(
                mdocQuery(
                    "mdl",
                    element("family_name"),
                    trustedAuthorities = listOf(
                        DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                            values = nonEmptyListOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y")
                        )
                    ),
                )
            )

            shouldThrow<IllegalArgumentException> { dcqlQuery.toIso180137AnnexCDeviceRequest() }
        }
    }
}
