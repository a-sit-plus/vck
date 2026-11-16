package at.asitplus.wallet.lib

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val RequestedPresentationTest by matrixSuite {
    val pid = RequestedCredential.SdJwt(
        vct = "urn:eudi:pid:1",
        JsonClaimReference("given_name"),
        id = "pid"
    )
    val mdl = RequestedCredential.Mdoc(
        docType = "org.iso.18013.5.1.mDL",
        MdocClaimReference("org.iso.18013.5.1", "driving_privileges"),
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
}
