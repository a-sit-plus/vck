package at.asitplus.wallet.lib

import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.IsoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

val RequestedCredentialTest by matrixSuite {

    "claim references" - {
        test("a claim is requested by a path of names") {
            JsonClaimReference("address", "street_address") shouldBe
                    JsonClaimReference(DCQLClaimsPathPointer("address", "street_address"))
        }

        test("a data element can be requested in the name space of the scheme") {
            val scheme = IsoMdocFallbackCredentialScheme(
                isoDocType = "org.example.doc",
                isoNamespace = "org.example.ns",
            )
            MdocClaimReference(scheme, "given_name") shouldBe
                    MdocClaimReference(namespace = "org.example.ns", claimName = "given_name")
        }
    }

    "credential schemes" - {
        test("a scheme provides the type identifier of each format") {
            RequestedCredential.SdJwt(AtomicAttribute2023).vct shouldBe AtomicAttribute2023.sdJwtType
            RequestedCredential.VcJwt(AtomicAttribute2023).type shouldBe AtomicAttribute2023.vcType
            RequestedCredential.Mdoc(AtomicAttribute2023).docType shouldBe AtomicAttribute2023.isoDocType
        }
    }

    "claim selections" - {
        test("without claims, no claim is requested") {
            RequestedCredential.SdJwt("urn:example:vct").claims shouldBe ClaimSelection.All()
        }

        test("claims passed as varargs are all required") {
            val givenName = JsonClaimReference("given_name")
            val familyName = JsonClaimReference("family_name")
            RequestedCredential.SdJwt("urn:example:vct", givenName, familyName).claims shouldBe
                    ClaimSelection.All(required = listOf(givenName, familyName))
        }

        test("a default ID is random, a given ID is kept") {
            RequestedCredential.Mdoc("org.iso.18013.5.1.mDL").id shouldNotBe
                    RequestedCredential.Mdoc("org.iso.18013.5.1.mDL").id
            val subjectName = JsonClaimReference("credentialSubject", "given_name")
            RequestedCredential.VcJwt("ExampleCredential", subjectName, id = "vc").id shouldBe "vc"
        }

        test("an ID that is not a valid ID of a DCQL Credential Query is rejected") {
            val invalidIds = listOf("", "pid.1", "pid 1", "pid/1")

            val failures = invalidIds.flatMap { id ->
                listOf(
                    { RequestedCredential.SdJwt("urn:eudi:pid:1", id = id) },
                    { RequestedCredential.VcJwt("ExampleCredential", id = id) },
                    { RequestedCredential.Mdoc("org.iso.18013.5.1.mDL", id = id) },
                ).map { runCatching(it).exceptionOrNull() }
            }

            failures.forEach { it.shouldBeInstanceOf<IllegalArgumentException>() }
        }

        "a claim requested twice is rejected" - {
            test("as required claim") {
                shouldThrow<IllegalArgumentException> {
                    ClaimSelection.All(listOf(JsonClaimReference("given_name"), JsonClaimReference("given_name")))
                }
            }
            test("as required claim and if available") {
                shouldThrow<IllegalArgumentException> {
                    ClaimSelection.All(
                        required = listOf(JsonClaimReference("credentialSubject", "given_name")),
                        ifAvailable = listOf(JsonClaimReference("credentialSubject", "given_name")),
                    )
                }
            }
            test("as data element") {
                shouldThrow<IllegalArgumentException> {
                    RequestedCredential.Mdoc(
                        "org.iso.18013.5.1.mDL",
                        MdocClaimReference("org.iso.18013.5.1", "given_name"),
                        MdocClaimReference("org.iso.18013.5.1", "given_name"),
                    )
                }
            }
        }

        test("the same name in different name spaces is two data elements") {
            val isoName = MdocClaimReference("org.iso.18013.5.1", "given_name")
            val aamvaName = MdocClaimReference("org.iso.18013.5.1.aamva", "given_name")
            RequestedCredential.Mdoc("org.iso.18013.5.1.mDL", isoName, aamvaName).claims shouldBe
                    ClaimSelection.All(required = listOf(isoName, aamvaName))
        }

        test("only requested data elements can be retained") {
            shouldThrow<IllegalArgumentException> {
                RequestedCredential.Mdoc(
                    "org.iso.18013.5.1.mDL",
                    MdocClaimReference("org.iso.18013.5.1", "family_name"),
                    intentToRetain = setOf(MdocClaimReference("org.iso.18013.5.1", "portrait")),
                )
            }
        }
    }

    "ISO DocRequest" - {
        test("requests the required data elements by name space, with their intent to retain, none if available") {
            val familyName = MdocClaimReference("org.iso.18013.5.1", "family_name")
            val compliance = MdocClaimReference("org.iso.18013.5.1.aamva", "DHS_compliance")
            val portrait = MdocClaimReference("org.iso.18013.5.1", "portrait")
            val mdoc = RequestedCredential.Mdoc(
                docType = "org.iso.18013.5.1.mDL",
                claims = ClaimSelection.All(required = listOf(familyName, compliance), ifAvailable = listOf(portrait)),
                intentToRetain = setOf(compliance),
            )

            val itemsRequest = mdoc.toDocRequest().itemsRequest.value

            itemsRequest.docType shouldBe "org.iso.18013.5.1.mDL"
            itemsRequest.namespaces shouldBe mapOf(
                "org.iso.18013.5.1" to ItemsRequestList(listOf(SingleItemsRequest("family_name", false))),
                "org.iso.18013.5.1.aamva" to ItemsRequestList(listOf(SingleItemsRequest("DHS_compliance", true))),
            )
        }

        test("with only data elements if available, no DocRequest can be created") {
            val portrait = MdocClaimReference("org.iso.18013.5.1", "portrait")
            val mdoc = RequestedCredential.Mdoc(
                docType = "org.iso.18013.5.1.mDL",
                claims = ClaimSelection.All(ifAvailable = listOf(portrait)),
            )

            shouldThrow<IllegalArgumentException> { mdoc.toDocRequest() }
        }

        test("without data elements, no DocRequest can be created") {
            shouldThrow<IllegalArgumentException> {
                RequestedCredential.Mdoc("org.iso.18013.5.1.mDL").toDocRequest()
            }
        }
    }
}
