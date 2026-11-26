package at.asitplus.wallet.lib

import at.asitplus.iso.IsoConstants
import at.asitplus.iso.UseCase
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val RequestedPresentationTest by matrixSuite {
    val pid = RequestedCredential.SdJwt(
        vct = "urn:eudi:pid:1",
        JsonClaimReference("given_name"),
        id = "pid"
    )
    val mdl = RequestedCredential.Mdoc(
        docType = MDL_DOCTYPE,
        MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.DRIVING_PRIVILEGES),
        id = "mdl",
    )
    val loyalty = RequestedCredential.VcJwt(
        type = "LoyaltyCredential",
        id = "loyalty"
    )

    "credential sets" - {
        test("oneOf is required, optional is not") {
            RequestedCredentialSet.oneOf(setOf(pid), setOf(mdl)) shouldBe
                    RequestedCredentialSet(options = listOf(setOf(pid), setOf(mdl)), required = true)
            RequestedCredentialSet.optional(setOf(loyalty)) shouldBe
                    RequestedCredentialSet(options = listOf(setOf(loyalty)), required = false)
        }

        test("the order of options matters, the order within an option does not") {
            RequestedCredentialSet.oneOf(setOf(pid), setOf(mdl)) shouldNotBe
                    RequestedCredentialSet.oneOf(setOf(mdl), setOf(pid))
            RequestedCredentialSet.oneOf(setOf(pid, mdl)) shouldBe RequestedCredentialSet.oneOf(setOf(mdl, pid))
        }

        test("options can be passed as a list, as from Java") {
            val options = listOf(setOf(pid), setOf(mdl))

            val required = RequestedCredentialSet.oneOf(options)
            val optional = RequestedCredentialSet.optional(options)

            required shouldBe RequestedCredentialSet.oneOf(setOf(pid), setOf(mdl))
            optional shouldBe RequestedCredentialSet.optional(setOf(pid), setOf(mdl))
        }

        "invalid sets are rejected" - {
            test("without options") {
                shouldThrow<IllegalArgumentException> { RequestedCredentialSet.oneOf() }
            }
            test("with an empty option") {
                shouldThrow<IllegalArgumentException> { RequestedCredentialSet.oneOf(setOf(pid), setOf()) }
            }
        }
    }

    "presentations" - {
        test("allOf requests every credential in one required set with one option") {
            RequestedPresentation.allOf(pid, mdl) shouldBe
                    RequestedPresentation(RequestedCredentialSet(listOf(setOf(pid, mdl)), required = true))
        }

        test("sets are passed as varargs") {
            val required = RequestedCredentialSet.oneOf(setOf(pid), setOf(mdl))
            val optional = RequestedCredentialSet.optional(setOf(loyalty))
            RequestedPresentation(required, optional) shouldBe RequestedPresentation(listOf(required, optional))
        }

        test("each credential is requested once, in the order of its first occurrence") {
            RequestedPresentation(
                RequestedCredentialSet.oneOf(setOf(pid, mdl), setOf(pid)),
                RequestedCredentialSet.optional(setOf(loyalty), setOf(pid)),
            ).credentials.toList() shouldBe listOf(pid, mdl, loyalty)
        }

        "invalid presentations are rejected" - {
            test("without sets") {
                shouldThrow<IllegalArgumentException> { RequestedPresentation(listOf()) }
            }
            test("without credentials") {
                shouldThrow<IllegalArgumentException> { RequestedPresentation.allOf() }
                    .message shouldBe "At least one credential is required"
            }
            test("without a required set") {
                shouldThrow<IllegalArgumentException> {
                    RequestedPresentation(RequestedCredentialSet.optional(setOf(pid)))
                }
            }
            test("with different credentials sharing an ID") {
                val familyName = JsonClaimReference("family_name")
                val otherPid = RequestedCredential.SdJwt("urn:eudi:pid:1", familyName, id = "pid")
                shouldThrow<IllegalArgumentException> {
                    RequestedPresentation(RequestedCredentialSet.oneOf(setOf(pid), setOf(otherPid)))
                }
            }
        }
    }

    "ISO DeviceRequest" - {
        val photoId = RequestedCredential.Mdoc(
            docType = "org.iso.23220.photoID.1",
            MdocClaimReference("org.iso.23220.1", "portrait"),
            id = "photoid",
        )
        val pidMdoc = RequestedCredential.Mdoc(
            docType = "eu.europa.ec.eudi.pid.1",
            MdocClaimReference("eu.europa.ec.eudi.pid.1", "age_over_18"),
            id = "pidmdoc",
        )

        test("requiring every mdoc has no use cases, in version 1.0") {
            val presentation = RequestedPresentation.allOf(mdl, photoId)

            val deviceRequest = presentation.toDeviceRequest()

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_0
                deviceRequestInfo shouldBe null
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf(mdl.docType, photoId.docType)
            }
        }

        test("alternative and optional mdocs are use cases with their purpose hints, in version 1.1") {
            val presentation = RequestedPresentation(
                RequestedCredentialSet(
                    options = listOf(setOf(pidMdoc), setOf(photoId)),
                    purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_AGE_VERIFICATION),
                ),
                RequestedCredentialSet.optional(setOf(mdl)),
            )

            val deviceRequest = presentation.toDeviceRequest()

            deviceRequest.apply {
                parsedVersion shouldBe IsoConstants.VERSION_1_1
                docRequests.map { it.itemsRequest.value.docType } shouldBe
                        listOf(pidMdoc.docType, photoId.docType, mdl.docType)
                deviceRequestInfo.shouldNotBeNull().value.useCases shouldBe listOf(
                    UseCase(
                        mandatory = true,
                        documentSets = listOf(listOf(0u), listOf(1u)),
                        purposeHints = mapOf(UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_AGE_VERIFICATION),
                    ),
                    UseCase(mandatory = false, documentSets = listOf(listOf(2u))),
                )
            }
        }

        test("purpose hints alone are a use case, in version 1.1") {
            val presentation = RequestedPresentation(
                RequestedCredentialSet(
                    options = listOf(setOf(mdl)),
                    purposeHints = mapOf(
                        UseCase.PURPOSE_CONTROLLER_ISO to UseCase.PURPOSE_DRIVING_PRIVILEGE_VERIFICATION
                    ),
                )
            )

            val deviceRequest = presentation.toDeviceRequest()

            deviceRequest.parsedVersion shouldBe IsoConstants.VERSION_1_1
        }

        test("other credentials than mdocs can not be requested") {
            val presentation = RequestedPresentation.allOf(mdl, pid)

            shouldThrow<IllegalArgumentException> { presentation.toDeviceRequest() }
        }

        test("an option contained in another one of its set can not be requested") {
            val presentation = RequestedPresentation(RequestedCredentialSet.oneOf(setOf(pidMdoc, mdl), setOf(pidMdoc)))

            shouldThrow<IllegalArgumentException> { presentation.toDeviceRequest() }
        }
    }
}
