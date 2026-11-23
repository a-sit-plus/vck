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
import at.asitplus.openid.dcql.DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier
import at.asitplus.openid.dcql.toIso180137AnnexCDeviceRequest
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.subjectKeyIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedCredentialSet
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MDL_NAMESPACE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

val RequestedPresentationQueryTest by matrixSuite {
    val givenName = JsonClaimReference("given_name")
    val address = JsonClaimReference("address", "street_address")
    val email = JsonClaimReference("email")
    val pidSdJwt = RequestedCredential.SdJwt(EU_PID_SD_JWT_VCT, givenName, id = "pid")
    val mdlMdoc = RequestedCredential.Mdoc(
        MDL_DOCTYPE,
        MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME),
        id = "mdl"
    )
    val loyaltyVcJwt = RequestedCredential.VcJwt("LoyaltyCredential", id = "loyalty")

    fun RequestedCredential.query() = CredentialPresentationRequestBuilder(this).toDCQLRequest().dcqlQuery
        .credentials.shouldBeSingleton().single()

    fun ids(vararg ids: String) = ids.map { DCQLClaimsQueryIdentifier(it) }
    fun credentialIds(vararg ids: String) = ids.map { DCQLCredentialQueryIdentifier(it) }

    "credential queries" - {
        test("an SD-JWT VC is queried by its vct, with its claims paths, all required") {
            RequestedCredential.SdJwt(
                EU_PID_SD_JWT_VCT,
                givenName, address,
                id = "pid"
            ).query()
                .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>().apply {
                    id shouldBe DCQLCredentialQueryIdentifier("pid")
                    meta.vctValues shouldBe listOf(EU_PID_SD_JWT_VCT)
                    claims?.toList() shouldBe listOf(
                        DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("given_name")),
                        DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("address", "street_address")),
                    )
                    claimSets.shouldBeNull()
                }
        }

        test("a credential is queried once from any issuer by default") {
            val credentials = listOf(pidSdJwt, mdlMdoc, loyaltyVcJwt)

            val queries = credentials.map { it.query() }

            queries.map { it.multiple } shouldBe listOf(false, false, false)
            queries.map { it.trustedAuthorities } shouldBe listOf(null, null, null)
        }

        test("multiple credentials from the issuers of trusted authorities are queried by their key identifiers") {
            val credential = RequestedCredential.SdJwt(
                EU_PID_SD_JWT_VCT,
                givenName,
                id = "pid",
                multiple = true,
                trustedAuthorities = setOf(
                    authority("s9tIpPmhxdiuNkHMEWNpYim8S8Y".decodeToByteArray(Base64UrlStrict)),
                    authority(byteArrayOf(1, 2, 3)),
                ),
            )

            val query = credential.query()

            query.multiple shouldBe true
            query.trustedAuthorities shouldBe nonEmptyListOf(
                DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier(
                    values = nonEmptyListOf("s9tIpPmhxdiuNkHMEWNpYim8S8Y", "AQID")
                )
            )
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
            val familyName = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME)
            val portrait = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
            RequestedCredential.Mdoc(
                MDL_DOCTYPE,
                familyName, portrait,
                intentToRetain = setOf(portrait),
            ).query().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>().apply {
                meta.doctypeValue shouldBe MDL_DOCTYPE
                claims?.toList() shouldBe listOf(
                    DCQLIsoMdocClaimsQuery(
                        path = DCQLClaimsPathPointer(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME)
                    ),
                    DCQLIsoMdocClaimsQuery(
                        path = DCQLClaimsPathPointer(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT),
                        intentToRetain = true,
                    ),
                )
            }
        }

        test("without claims, claims are absent") {
            RequestedCredential.SdJwt(EU_PID_SD_JWT_VCT).query().apply {
                claims.shouldBeNull()
                claimSets.shouldBeNull()
            }
        }
    }

    "claim combinations" - {
        test("claims if available are one bundle: all claims, or the required ones") {
            RequestedCredential.SdJwt(
                EU_PID_SD_JWT_VCT,
                ClaimSelection.All(required = setOf(givenName), ifAvailable = setOf(address, email)),
            ).query().apply {
                claims?.map { it.id } shouldBe ids("0", "1", "2")
                claims?.map { it.path } shouldBe listOf(givenName.path, address.path, email.path)
                claimSets?.toList() shouldBe listOf(ids("0", "1", "2"), ids("0"))
            }
        }

        test("only claims if available fall back to no claim") {
            RequestedCredential.SdJwt(
                EU_PID_SD_JWT_VCT,
                ClaimSelection.All(ifAvailable = setOf(address))
            ).query()
                .claimSets?.toList() shouldBe listOf(ids("0"), ids())
        }

        test("alternatives are claim combinations of the common claims and each option, in order") {
            val familyName = JsonClaimReference("family_name")
            RequestedCredential.SdJwt(
                EU_PID_SD_JWT_VCT,
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
                    listOf(MDL_DOCTYPE, "org.example.doc")
        }

        "is the same as through DCQL, as both use one set of rules" - {
            val familyName = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.FAMILY_NAME)
            val portrait = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.PORTRAIT)
            val ageOver18 = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.AGE_OVER_18)
            val ageInYears = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.AGE_IN_YEARS)
            val birthDate = MdocClaimReference(MDL_NAMESPACE, MobileDrivingLicenceDataElements.BIRTH_DATE)
            val other =
                RequestedCredential.Mdoc("org.example.doc", MdocClaimReference("org.example", "x"), id = "other")
            listOf(
                SameRequest("for data elements if available, retained") {
                    RequestedPresentation.allOf(
                        RequestedCredential.Mdoc(
                            MDL_DOCTYPE,
                            ClaimSelection.All(required = setOf(familyName), ifAvailable = setOf(portrait)),
                            intentToRetain = setOf(familyName),
                        )
                    )
                },
                SameRequest("for alternative data elements with common ones") {
                    RequestedPresentation.allOf(
                        RequestedCredential.Mdoc(
                            MDL_DOCTYPE,
                            ClaimSelection.Alternatives(
                                setOf(ageOver18), setOf(ageInYears), setOf(birthDate),
                                common = setOf(familyName),
                            ),
                        )
                    )
                },
                SameRequest("for alternative and optional credentials") {
                    RequestedPresentation(
                        RequestedCredentialSet.oneOf(setOf(mdlMdoc), setOf(other)),
                        RequestedCredentialSet.optional(setOf(mdlMdoc, other)),
                    )
                },
                SameRequest("for multiple credentials from trusted authorities") {
                    RequestedPresentation.allOf(
                        RequestedCredential.Mdoc(
                            MDL_DOCTYPE,
                            familyName,
                            multiple = true,
                            trustedAuthorities = setOf(authority(byteArrayOf(1, 2, 3))),
                        )
                    )
                },
            ).asData(nameFn = { it.name }) test { case ->
                val builder = CredentialPresentationRequestBuilder(case.presentation())

                val direct = builder.toIsoDeviceRetrievalRequest().deviceRequest
                val throughDcql = builder.toDCQLRequest().dcqlQuery.toIso180137AnnexCDeviceRequest()

                direct shouldBe throughDcql
            }
        }

        "can not express" - {
            test("other credentials than mdocs") {
                shouldThrow<IllegalArgumentException> {
                    CredentialPresentationRequestBuilder(mdlMdoc, pidSdJwt)
                        .toIsoDeviceRetrievalRequest()
                }
            }
        }
    }
}

/** A typed presentation whose ISO request is the same, whether converted directly or through DCQL. */
private data class SameRequest(val name: String, val presentation: suspend () -> RequestedPresentation)

/** A self-signed certificate with the subject key identifier [keyIdentifier], as of a certificate authority. */
private suspend fun authority(keyIdentifier: ByteArray): X509Certificate = EphemeralKeyWithSelfSignedCert(
    extensions = listOf(
        X509CertificateExtension(
            oid = KnownOIDs.subjectKeyIdentifier,
            value = Asn1EncapsulatingOctetString(listOf(Asn1.OctetString(keyIdentifier))),
        )
    )
).getCertificate().shouldNotBeNull()
