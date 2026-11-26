package at.asitplus.wallet.lib

import at.asitplus.iso.AlternativeDataElementsSet
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.IsoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
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
                    ClaimSelection.All(required = setOf(givenName, familyName))
        }

        test("the order of claims does not matter") {
            val givenName = JsonClaimReference("given_name")
            val familyName = JsonClaimReference("family_name")
            ClaimSelection.All(setOf(givenName, familyName)) shouldBe ClaimSelection.All(setOf(familyName, givenName))
        }

        test("a default ID is random, a given ID is kept") {
            RequestedCredential.Mdoc(MDL_DOCTYPE).id shouldNotBe RequestedCredential.Mdoc(MDL_DOCTYPE).id
            val subjectName = JsonClaimReference("credentialSubject", "given_name")
            RequestedCredential.VcJwt("ExampleCredential", subjectName, id = "vc").id shouldBe "vc"
        }

        test("an ID that is not a valid ID of a DCQL Credential Query is rejected") {
            val invalidIds = listOf("", "pid.1", "pid 1", "pid/1")

            val failures = invalidIds.flatMap { id ->
                listOf(
                    { RequestedCredential.SdJwt(EU_PID_SD_JWT_VCT, id = id) },
                    { RequestedCredential.VcJwt("ExampleCredential", id = id) },
                    { RequestedCredential.Mdoc(MDL_DOCTYPE, id = id) },
                ).map { runCatching(it).exceptionOrNull() }
            }

            failures.forEach { it.shouldBeInstanceOf<IllegalArgumentException>() }
        }

        test("a claim passed twice as vararg is requested once") {
            val givenName = JsonClaimReference("given_name")
            RequestedCredential.SdJwt("urn:example:vct", givenName, givenName).claims shouldBe
                    ClaimSelection.All(setOf(givenName))
            val isoName = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.GIVEN_NAME)
            RequestedCredential.Mdoc(MDL_DOCTYPE, isoName, isoName).claims shouldBe
                    ClaimSelection.All(setOf(isoName))
        }

        test("a claim both required and requested if available is rejected") {
            shouldThrow<IllegalArgumentException> {
                ClaimSelection.All(
                    required = setOf(JsonClaimReference("credentialSubject", "given_name")),
                    ifAvailable = setOf(JsonClaimReference("credentialSubject", "given_name")),
                )
            }
        }

        test("the same name in different name spaces is two data elements") {
            val isoName = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.GIVEN_NAME)
            val aamvaName = MdocClaimReference(AAMVA_NAMESPACE, "given_name")
            RequestedCredential.Mdoc(MDL_DOCTYPE, isoName, aamvaName).claims shouldBe
                    ClaimSelection.All(required = setOf(isoName, aamvaName))
        }

        test("only requested data elements can be retained") {
            shouldThrow<IllegalArgumentException> {
                RequestedCredential.Mdoc(
                    docType = MDL_DOCTYPE,
                    MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME),
                    intentToRetain = setOf(
                        MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
                    ),
                )
            }
        }
    }

    "claim alternatives" - {
        val lastName = JsonClaimReference("last_name")
        val postalCode = JsonClaimReference("postal_code")
        val locality = JsonClaimReference("locality")
        val region = JsonClaimReference("region")

        test("options are passed as varargs, in the order of preference, with the common claims") {
            val selection = ClaimSelection.Alternatives(
                setOf(postalCode),
                setOf(locality, region),
                common = setOf(lastName),
            )
            selection shouldBe ClaimSelection.Alternatives(
                options = listOf(setOf(postalCode), setOf(locality, region)),
                common = setOf(lastName),
            )
        }

        test("the order of options matters") {
            ClaimSelection.Alternatives(setOf(postalCode), setOf(locality)) shouldNotBe
                    ClaimSelection.Alternatives(setOf(locality), setOf(postalCode))
        }

        test("a credential can request alternatives") {
            val selection = ClaimSelection.Alternatives(setOf(JsonClaimReference("age_over_18")), setOf(lastName))
            RequestedCredential.SdJwt("urn:example:vct", selection).claims shouldBe selection
        }

        test("one claim may occur in several options") {
            ClaimSelection.Alternatives(setOf(lastName, postalCode), setOf(lastName, locality)).options shouldBe
                    listOf(setOf(lastName, postalCode), setOf(lastName, locality))
        }

        test("an empty option accepts the credential with the common claims only") {
            ClaimSelection.Alternatives(setOf(postalCode), setOf(), common = setOf(lastName)).options shouldBe
                    listOf(setOf(postalCode), setOf())
        }

        "invalid alternatives are rejected" - {
            test("without options") {
                shouldThrow<IllegalArgumentException> {
                    ClaimSelection.Alternatives(options = listOf(), common = setOf(lastName))
                }
            }
            test("without any claim") {
                shouldThrow<IllegalArgumentException> {
                    ClaimSelection.Alternatives(setOf<JsonClaimReference>(), setOf())
                }
            }
            test("with a claim in the common claims and an option") {
                shouldThrow<IllegalArgumentException> {
                    ClaimSelection.Alternatives(
                        setOf(lastName, postalCode),
                        setOf(locality),
                        common = setOf(lastName),
                    )
                }
            }
        }

        test("data elements of any option can be retained") {
            val portrait = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
            val ageOver18 = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.AGE_OVER_18)
            RequestedCredential.Mdoc(
                docType = MDL_DOCTYPE,
                claims = ClaimSelection.Alternatives(setOf(ageOver18), setOf(portrait)),
                intentToRetain = setOf(portrait),
            ).intentToRetain shouldBe setOf(portrait)
        }
    }

    "ISO DocRequest" - {
        test("requests the required data elements by name space, with their intent to retain, none if available") {
            val familyName = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME)
            val compliance = MdocClaimReference(AAMVA_NAMESPACE, "DHS_compliance")
            val portrait = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
            val mdoc = RequestedCredential.Mdoc(
                docType = MDL_DOCTYPE,
                claims = ClaimSelection.All(required = setOf(familyName, compliance), ifAvailable = setOf(portrait)),
                intentToRetain = setOf(compliance),
            )

            val itemsRequest = mdoc.toDocRequest().itemsRequest.value

            itemsRequest.docType shouldBe mdoc.docType
            itemsRequest.namespaces shouldBe mapOf(
                MDL_NAMESPACE to ItemsRequestList(
                    listOf(SingleItemsRequest(MobileDrivingLicenceDataElements.FAMILY_NAME, false))
                ),
                AAMVA_NAMESPACE to ItemsRequestList(listOf(SingleItemsRequest("DHS_compliance", true))),
            )
        }

        test("with only data elements if available, no DocRequest can be created") {
            val portrait = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
            val mdoc = RequestedCredential.Mdoc(
                docType = MDL_DOCTYPE,
                claims = ClaimSelection.All(ifAvailable = setOf(portrait)),
            )

            shouldThrow<IllegalArgumentException> { mdoc.toDocRequest() }
        }

        test("requests alternative data elements as alternatives of the first option") {
            val ageOver18 = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.AGE_OVER_18)
            val birthDate = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.BIRTH_DATE)
            val mdoc = RequestedCredential.Mdoc(
                docType = MDL_DOCTYPE,
                claims = ClaimSelection.Alternatives(setOf(ageOver18), setOf(birthDate)),
            )

            val itemsRequest = mdoc.toDocRequest().itemsRequest.value

            itemsRequest.apply {
                namespaces shouldBe mapOf(
                    MDL_NAMESPACE to ItemsRequestList(
                        listOf(SingleItemsRequest(MobileDrivingLicenceDataElements.AGE_OVER_18, false))
                    )
                )
                requestInfo.shouldNotBeNull().alternativeDataElements shouldBe listOf(
                    AlternativeDataElementsSet(
                        requestedElement = ElementReference(
                            MDL_NAMESPACE,
                            MobileDrivingLicenceDataElements.AGE_OVER_18
                        ),
                        alternativeElementSets = listOf(
                            listOf(ElementReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.BIRTH_DATE))
                        ),
                    )
                )
            }
        }

        test("without data elements, no DocRequest can be created") {
            shouldThrow<IllegalArgumentException> {
                RequestedCredential.Mdoc(MDL_DOCTYPE).toDocRequest()
            }
        }
    }
}


private const val AAMVA_NAMESPACE = "org.iso.18013.5.1.aamva"