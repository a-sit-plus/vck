package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialSetQuery
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLJwtVcCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedCredentialSet
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val RequestedPresentationQueryTest by matrixSuite {
    val givenName = JsonClaimReference("given_name")
    val address = JsonClaimReference("address", "street_address")
    val email = JsonClaimReference("email")
    val pidSdJwt = RequestedCredential.SdJwt("urn:eudi:pid:1", givenName, id = "pid")
    val mdlMdoc = RequestedCredential.Mdoc("org.iso.18013.5.1.mDL",
        MdocClaimReference("org.iso.18013.5.1", "family_name"), id = "mdl")
    val loyaltyVcJwt = RequestedCredential.VcJwt("LoyaltyCredential", id = "loyalty")

    fun RequestedCredential.query() = CredentialPresentationRequestBuilder(this).toDCQLRequest().dcqlQuery
        .credentials.shouldBeSingleton().single()

    fun ids(vararg ids: String) = ids.map { DCQLClaimsQueryIdentifier(it) }
    fun credentialIds(vararg ids: String) = ids.map { DCQLCredentialQueryIdentifier(it) }

    "credential queries" - {
        test("an SD-JWT VC is queried by its vct, with its claims paths, all required") {
            RequestedCredential.SdJwt(
                "urn:eudi:pid:1",
                givenName, address,
                id = "pid"
            ).query()
                .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>().apply {
                    id shouldBe DCQLCredentialQueryIdentifier("pid")
                    meta.vctValues shouldBe listOf("urn:eudi:pid:1")
                    claims?.toList() shouldBe listOf(
                        DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("given_name")),
                        DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("address", "street_address")),
                    )
                    claimSets.shouldBeNull()
                }
        }

        test("a VC-JWT is queried by its type, with claims paths from the root of the VC") {
            RequestedCredential.VcJwt(
                "ExampleCredential",
                JsonClaimReference("credentialSubject", "given_name")
            ).query()
                .shouldBeInstanceOf<DCQLJwtVcCredentialQuery>().apply {
                    meta.typeValues.toList() shouldBe listOf(listOf("ExampleCredential"))
                    claims?.toList() shouldBe listOf(
                        DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("credentialSubject", "given_name"))
                    )
                }
        }

        test("an mdoc is queried by its doctype, with its data elements and intent to retain") {
            val familyName = MdocClaimReference("org.iso.18013.5.1", "family_name")
            val portrait = MdocClaimReference("org.iso.18013.5.1", "portrait")
            RequestedCredential.Mdoc(
                "org.iso.18013.5.1.mDL",
                familyName, portrait,
                intentToRetain = setOf(portrait),
            ).query().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>().apply {
                meta.doctypeValue shouldBe "org.iso.18013.5.1.mDL"
                claims?.toList() shouldBe listOf(
                    DCQLIsoMdocClaimsQuery(path = DCQLClaimsPathPointer("org.iso.18013.5.1", "family_name")),
                    DCQLIsoMdocClaimsQuery(
                        path = DCQLClaimsPathPointer("org.iso.18013.5.1", "portrait"),
                        intentToRetain = true,
                    ),
                )
            }
        }

        test("without claims, claims are absent") {
            RequestedCredential.SdJwt("urn:eudi:pid:1").query().apply {
                claims.shouldBeNull()
                claimSets.shouldBeNull()
            }
        }
    }

    "claim combinations" - {
        test("claims if available are one bundle: all claims, or the required ones") {
            RequestedCredential.SdJwt(
                "urn:eudi:pid:1",
                ClaimSelection.All(required = setOf(givenName), ifAvailable = setOf(address, email)),
            ).query().apply {
                claims?.map { it.id } shouldBe ids("0", "1", "2")
                claims?.map { it.path } shouldBe listOf(givenName.path, address.path, email.path)
                claimSets?.toList() shouldBe listOf(ids("0", "1", "2"), ids("0"))
            }
        }

        test("only claims if available fall back to no claim") {
            RequestedCredential.SdJwt(
                "urn:eudi:pid:1",
                ClaimSelection.All(ifAvailable = setOf(address))
            ).query()
                .claimSets?.toList() shouldBe listOf(ids("0"), ids())
        }

        test("alternatives are claim combinations of the common claims and each option, in order") {
            val familyName = JsonClaimReference("family_name")
            RequestedCredential.SdJwt(
                "urn:eudi:pid:1",
                ClaimSelection.Alternatives(
                    setOf(address, email),
                    setOf(address, givenName),
                    common = setOf(familyName),
                ),
            ).query().apply {
                claims?.map { it.path } shouldBe listOf(familyName.path, address.path, email.path, givenName.path)
                claimSets?.toList() shouldBe listOf(ids("0", "1", "2"), ids("0", "1", "3"))
            }
        }
    }

    "credential sets" - {
        test("requiring every credential omits credential_sets") {
            CredentialPresentationRequestBuilder(
                pidSdJwt, mdlMdoc
            ).toDCQLRequest().dcqlQuery.apply {
                credentials.map { it.id } shouldBe credentialIds("pid", "mdl")
                credentialSets.shouldBeNull()
            }
        }

        test("several required sets with one option each require every credential, so credential_sets is omitted") {
            val presentation = RequestedPresentation(
                RequestedCredentialSet.oneOf(setOf(pidSdJwt)),
                RequestedCredentialSet.oneOf(setOf(mdlMdoc)),
            )

            val query = CredentialPresentationRequestBuilder(presentation).toDCQLRequest().dcqlQuery

            query.credentials.map { it.id } shouldBe credentialIds("pid", "mdl")
            query.credentialSets.shouldBeNull()
        }

        test("alternative and optional credentials are credential sets, each credential queried once") {
            CredentialPresentationRequestBuilder(
                RequestedPresentation(
                    RequestedCredentialSet.oneOf(setOf(pidSdJwt, mdlMdoc), setOf(pidSdJwt)),
                    RequestedCredentialSet.optional(setOf(loyaltyVcJwt)),
                )
            ).toDCQLRequest().dcqlQuery.apply {
                credentials.map { it.id.string } shouldBe listOf("pid", "mdl", "loyalty")
                credentialSets?.toList() shouldBe listOf(
                    DCQLCredentialSetQuery(
                        options = nonEmptyListOf(credentialIds("pid", "mdl"), credentialIds("pid")),
                        required = true,
                    ),
                    DCQLCredentialSetQuery(options = nonEmptyListOf(credentialIds("loyalty")), required = false),
                )
            }
        }

        test("the query round-trips through JSON") {
            val query = CredentialPresentationRequestBuilder(
                RequestedPresentation(
                    RequestedCredentialSet.oneOf(setOf(pidSdJwt, mdlMdoc), setOf(pidSdJwt)),
                    RequestedCredentialSet.optional(setOf(loyaltyVcJwt)),
                )
            ).toDCQLRequest().dcqlQuery
            val serialized = joseCompliantSerializer.encodeToString(DCQLQuery.serializer(), query)
            joseCompliantSerializer.decodeFromString(DCQLQuery.serializer(), serialized) shouldBe query
        }
    }

    "ISO DeviceRequest" - {
        test("requests every mdoc, also from several required sets with one option each") {
            val other = RequestedCredential.Mdoc("org.example.doc", MdocClaimReference("org.example", "x"))
            val presentation = RequestedPresentation(
                RequestedCredentialSet.oneOf(setOf(mdlMdoc)),
                RequestedCredentialSet.oneOf(setOf(other)),
            )
            CredentialPresentationRequestBuilder(presentation).toIsoDeviceRetrievalRequest()
                .deviceRequest.docRequests.map { it.itemsRequest.value.docType } shouldBe
                    listOf("org.iso.18013.5.1.mDL", "org.example.doc")
        }

        "can not express" - {
            test("alternative credentials") {
                val other = RequestedCredential.Mdoc("org.example.doc", MdocClaimReference("org.example", "x"))
                shouldThrow<IllegalArgumentException> {
                    CredentialPresentationRequestBuilder(
                        RequestedPresentation(
                            RequestedCredentialSet.oneOf(setOf(mdlMdoc), setOf(other))
                        )
                    ).toIsoDeviceRetrievalRequest()
                }
            }
            test("optional credentials") {
                shouldThrow<IllegalArgumentException> {
                    CredentialPresentationRequestBuilder(
                        RequestedPresentation(
                            RequestedCredentialSet.oneOf(setOf(mdlMdoc)),
                            RequestedCredentialSet.optional(setOf(mdlMdoc)),
                        )
                    ).toIsoDeviceRetrievalRequest()
                }
            }
            test("other credentials than mdocs") {
                shouldThrow<IllegalArgumentException> {
                    CredentialPresentationRequestBuilder(mdlMdoc, pidSdJwt)
                        .toIsoDeviceRetrievalRequest()
                }
            }
        }
    }
}
