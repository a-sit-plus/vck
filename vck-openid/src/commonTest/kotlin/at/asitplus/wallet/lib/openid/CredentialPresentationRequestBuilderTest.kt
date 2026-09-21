@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString


val CredentialPresentationRequestBuilderTest by matrixSuite {
    test("invalid credential scheme for SD-JWT should not throw when creating query") {
        val credential = RequestOptionsCredential(
            credentialScheme = object : SdJwtCredentialScheme {
                override val sdJwtType: String
                    get() = "something"
            },
            representation = SD_JWT
        )

        CredentialPresentationRequestBuilder(credential).apply {
            toDCQLRequest()
            toPresentationExchangeRequest()
            shouldThrowAny {
                toIsoDeviceRetrievalRequest()
            }
        }
    }

    test("invalid credential scheme for ISO should not throw when creating query") {
        val credential = RequestOptionsCredential(
            credentialScheme = object : IsoMdocCredentialScheme {
                override val isoDocType: String
                    get() = "something"
                override val isoNamespace: String
                    get() = "else"
            },
            representation = ISO_MDOC
        )
        CredentialPresentationRequestBuilder(credential).apply {
            toDCQLRequest()
            toPresentationExchangeRequest()
            toIsoDeviceRetrievalRequest()
        }
    }

    test("sd-jwt dcql mapping includes metadata and claims") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                optionalAttributePaths = setOf(DCQLClaimsPathPointer(CLAIM_FAMILY_NAME)),
                id = "cred-1"
            )
        )

        builder.toDCQLRequest().shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>().apply {
                meta.shouldBeInstanceOf<DCQLSdJwtCredentialMetadataAndValidityConstraints>()
                    .vctValues shouldContain ConstantIndex.AtomicAttribute2023.sdJwtType

                claims.shouldNotBeNull()
                    .toList().shouldHaveSize(2)
                    .map {
                        it.shouldBeInstanceOf<DCQLJsonClaimsQuery>().path.segments.first()
                            .shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
                            .name
                    }.toSet() shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)
            }
    }

    test("sd-jwt dcql mapping supports literal dot claim names with typed paths") {
        val dotClaimName = "foo.bar"
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer(dotClaimName)),
                id = "cred-1"
            )
        )

        builder.toDCQLRequest().shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
            .name shouldBe dotClaimName
    }

    test("sd-jwt dcql mapping supports nested typed paths") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer("foo", "bar")),
                id = "cred-1"
            )
        )

        builder.toDCQLRequest().shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments.map {
                it.shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>().name
            } shouldBe listOf("foo", "bar")
    }

    test("iso mdoc mapping includes namespace and doctype") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                id = "cred-1"
            )
        )

        builder.toDCQLRequest().shouldNotBeNull().dcqlQuery.shouldNotBeNull()
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>().apply {
                meta.shouldBeInstanceOf<DCQLIsoMdocCredentialMetadataAndValidityConstraints>()
                    .doctypeValue shouldBe ConstantIndex.AtomicAttribute2023.isoDocType

                claims.shouldNotBeNull().shouldBeSingleton().first()
                    .shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>().apply {
                        namespace shouldBe ConstantIndex.AtomicAttribute2023.isoNamespace
                        claimName shouldBe CLAIM_GIVEN_NAME
                    }
            }

        builder.toIsoDeviceRetrievalRequest().shouldNotBeNull().deviceRequest.apply {
            docRequests.shouldBeSingleton().first()
                .itemsRequest.value.apply {
                    docType shouldBe ConstantIndex.AtomicAttribute2023.isoDocType
                    namespaces.entries.shouldBeSingleton().first().apply {
                        key shouldBe ConstantIndex.AtomicAttribute2023.isoNamespace
                        value.entries.shouldBeSingleton().first().apply {
                            dataElementIdentifier shouldBe CLAIM_GIVEN_NAME
                        }
                    }
                }
        }
    }

    test("iso mdoc mapping supports explicit namespace claim paths") {
        val namespace = "custom.namespace"
        val claimName = "custom_claim"
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(namespace, claimName)),
                id = "cred-1"
            )
        )

        builder.toDCQLRequest().shouldNotBeNull().dcqlQuery.shouldNotBeNull()
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>().apply {
                namespace shouldBe namespace
                claimName shouldBe claimName
            }

        builder.toIsoDeviceRetrievalRequest().shouldNotBeNull().deviceRequest.apply {
            docRequests.shouldBeSingleton().first()
                .itemsRequest.value.apply {
                    docType shouldBe ConstantIndex.AtomicAttribute2023.isoDocType
                    namespaces.entries.shouldBeSingleton().first().apply {
                        key shouldBe namespace
                        value.entries.shouldBeSingleton().first().apply {
                            dataElementIdentifier shouldBe claimName
                        }
                    }
                }
        }
    }

    test("ISO Device Retrieval presentation requests survive JSON round trips") {
        val request = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            )
        ).toIsoDeviceRetrievalRequest().shouldNotBeNull()

        joseCompliantSerializer.decodeFromString<CredentialPresentationRequest>(
            joseCompliantSerializer.encodeToString<CredentialPresentationRequest>(request)
        ) shouldBe request
    }

    test("iso device retrieval merges claims that land in the same namespace") {
        // Regression: a one-segment path (default namespace) plus a two-segment path whose namespace equals that
        // same default namespace must both survive, instead of one silently overwriting the other.
        val request = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(
                    DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                    DCQLClaimsPathPointer(ConstantIndex.AtomicAttribute2023.isoNamespace, CLAIM_FAMILY_NAME),
                ),
            )
        ).toIsoDeviceRetrievalRequest()

        request.deviceRequest.docRequests.shouldBeSingleton().first()
            .itemsRequest.value.namespaces
            .getValue(ConstantIndex.AtomicAttribute2023.isoNamespace).entries
            .map { it.dataElementIdentifier }.toSet() shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)
    }

}
