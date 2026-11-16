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
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtFallbackCredentialScheme
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val RequestOptionsCredentialBridgeTest by matrixSuite {
    val customSdJwtScheme = object : SdJwtCredentialScheme {
        override val sdJwtType: String
            get() = "something"
    }
    val customIsoScheme = object : IsoMdocCredentialScheme {
        override val isoDocType: String
            get() = "something"
        override val isoNamespace: String
            get() = "else"
    }

    test("an SD-JWT request of a custom scheme is queried by DCQL") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(credentialScheme = customSdJwtScheme, representation = SD_JWT)
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .meta.shouldBeInstanceOf<DCQLSdJwtCredentialMetadataAndValidityConstraints>()
            .vctValues shouldContain "something"
    }

    test("an SD-JWT request can not be an ISO device request") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(credentialScheme = customSdJwtScheme, representation = SD_JWT)
        )

        val result = runCatching { builder.toIsoDeviceRetrievalRequest() }

        result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
    }

    test("an ISO request without data elements is queried by DCQL without claims") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(credentialScheme = customIsoScheme, representation = ISO_MDOC)
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()
            .claims.shouldBeNull()
    }

    test("an ISO request without data elements can not be an ISO device request") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(credentialScheme = customIsoScheme, representation = ISO_MDOC)
        )

        val result = runCatching { builder.toIsoDeviceRetrievalRequest() }

        result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
    }

    test("sd-jwt dcql mapping includes metadata and claims") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                optionalAttributePaths = setOf(DCQLClaimsPathPointer(CLAIM_FAMILY_NAME)),
                id = "cred-1"
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLSdJwtCredentialQuery>().apply {
            meta.shouldBeInstanceOf<DCQLSdJwtCredentialMetadataAndValidityConstraints>()
                .vctValues shouldContain AtomicAttribute2023.sdJwtType
            claims.shouldNotBeNull().toList().shouldHaveSize(2).map {
                it.shouldBeInstanceOf<DCQLJsonClaimsQuery>().path.segments.first()
                    .shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>().name
            }.toSet() shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)
        }
    }

    test("sd-jwt dcql mapping supports literal dot claim names with typed paths") {
        val dotClaimName = "foo.bar"
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer(dotClaimName)),
                id = "cred-1"
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments.shouldBeSingleton().first().shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
            .name shouldBe dotClaimName
    }

    test("sd-jwt dcql mapping supports nested typed paths") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer("foo", "bar")),
                id = "cred-1"
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments.map {
                it.shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>().name
            } shouldBe listOf("foo", "bar")
    }

    test("iso mdoc dcql mapping includes namespace and doctype") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                id = "cred-1"
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>().apply {
            meta.shouldBeInstanceOf<DCQLIsoMdocCredentialMetadataAndValidityConstraints>()
                .doctypeValue shouldBe AtomicAttribute2023.isoDocType
            claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>().apply {
                namespace shouldBe AtomicAttribute2023.isoNamespace
                claimName shouldBe CLAIM_GIVEN_NAME
            }
        }
    }

    test("iso device retrieval includes namespace and doctype") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                id = "cred-1"
            )
        )

        val request = builder.toIsoDeviceRetrievalRequest()

        request.deviceRequest.docRequests.shouldBeSingleton().first().itemsRequest.value.apply {
            docType shouldBe AtomicAttribute2023.isoDocType
            namespaces.entries.shouldBeSingleton().first().apply {
                key shouldBe AtomicAttribute2023.isoNamespace
                value.entries.shouldBeSingleton().first().dataElementIdentifier shouldBe CLAIM_GIVEN_NAME
            }
        }
    }

    test("iso mdoc dcql mapping supports explicit namespace claim paths") {
        val customNamespace = "custom.namespace"
        val customClaimName = "custom_claim"
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(customNamespace, customClaimName)),
                id = "cred-1"
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>().apply {
                namespace shouldBe customNamespace
                claimName shouldBe customClaimName
            }
    }

    test("iso device retrieval supports explicit namespace claim paths") {
        val customNamespace = "custom.namespace"
        val customClaimName = "custom_claim"
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(customNamespace, customClaimName)),
                id = "cred-1"
            )
        )

        val request = builder.toIsoDeviceRetrievalRequest()

        request.deviceRequest.docRequests.shouldBeSingleton().first().itemsRequest.value.apply {
            docType shouldBe AtomicAttribute2023.isoDocType
            namespaces.entries.shouldBeSingleton().first().apply {
                key shouldBe customNamespace
                value.entries.shouldBeSingleton().first().dataElementIdentifier shouldBe customClaimName
            }
        }
    }

    test("ISO Device Retrieval presentation requests survive JSON round trips") {
        val request: CredentialPresentationRequest = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            )
        ).toIsoDeviceRetrievalRequest()

        val decoded = joseCompliantSerializer.decodeFromString<CredentialPresentationRequest>(
            joseCompliantSerializer.encodeToString<CredentialPresentationRequest>(request)
        )

        decoded shouldBe request
    }

    test("iso device retrieval merges claims that land in the same namespace") {
        // Regression: a one-segment path (default namespace) plus a two-segment path whose namespace equals that
        // same default namespace must both survive, instead of one silently overwriting the other.
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(
                    DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                    DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_FAMILY_NAME),
                ),
            )
        )

        val request = builder.toIsoDeviceRetrievalRequest()

        request.deviceRequest.docRequests.shouldBeSingleton().first()
            .itemsRequest.value.namespaces
            .getValue(AtomicAttribute2023.isoNamespace).entries
            .map { it.dataElementIdentifier }.toSet() shouldBe setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)
    }

    test("iso mdoc reads a data element once, however its pointer names it") {
        val pointers = setOf(
            DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
            DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME),
        )
        val expected = MdocClaimReference(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME)

        val credential = RequestOptionsCredential(
            credentialScheme = AtomicAttribute2023,
            representation = ISO_MDOC,
            attributePaths = pointers,
            optionalAttributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
        )

        credential.requestedMdocClaims shouldBe setOf(expected)
        credential.requestedOptionalMdocClaims shouldBe setOf(expected)
    }

    test("iso mdoc dcql mapping queries a data element once, however its pointer names it") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(
                    DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                    DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME),
                ),
                optionalAttributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>().apply {
                namespace shouldBe AtomicAttribute2023.isoNamespace
                claimName shouldBe CLAIM_GIVEN_NAME
            }
    }

    test("iso device retrieval requests only the required data elements") {
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                optionalAttributePaths = setOf(DCQLClaimsPathPointer(CLAIM_FAMILY_NAME)),
            )
        )

        val request = builder.toIsoDeviceRetrievalRequest()

        request.deviceRequest.docRequests.shouldBeSingleton().first()
            .itemsRequest.value.namespaces
            .getValue(AtomicAttribute2023.isoNamespace).entries
            .map { it.dataElementIdentifier }.toSet() shouldBe setOf(CLAIM_GIVEN_NAME)
    }

    test("iso mdoc rejects pointers that name no data element") {
        val pointers = listOf(
            DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME, "nested"),
            DCQLClaimsPathPointer(
                DCQLClaimsPathPointerSegment.NameSegment(AtomicAttribute2023.isoNamespace),
                DCQLClaimsPathPointerSegment.IndexSegment(0u),
            ),
            DCQLClaimsPathPointer(null),
        )

        val failures = pointers.flatMap { pointer ->
            listOf(
                runCatching {
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, attributePaths = setOf(pointer))
                },
                runCatching {
                    RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, optionalAttributePaths = setOf(pointer))
                },
            ).map { it.exceptionOrNull() }
        }

        failures.forEach { it.shouldBeInstanceOf<IllegalArgumentException>() }
    }

    test("iso mdoc rejects a data element identifier without a name space") {
        val scheme = object : CredentialScheme {
            override val isoDocType: String
                get() = "something"
        }

        val result = runCatching {
            RequestOptionsCredential(
                credentialScheme = scheme,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            )
        }

        result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
    }

    test("iso mdoc accepts a data element with its name space for a scheme without one") {
        val scheme = object : CredentialScheme {
            override val isoDocType: String
                get() = "something"
        }

        val credential = RequestOptionsCredential(
            credentialScheme = scheme,
            representation = ISO_MDOC,
            attributePaths = setOf(DCQLClaimsPathPointer("custom.namespace", CLAIM_GIVEN_NAME)),
        )

        credential.requestedMdocClaims shouldBe setOf(MdocClaimReference("custom.namespace", CLAIM_GIVEN_NAME))
    }

    test("json representations request no mdoc data elements") {
        val pointer = DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME, "nested")

        val credential = RequestOptionsCredential(
            credentialScheme = AtomicAttribute2023,
            representation = SD_JWT,
            attributePaths = setOf(pointer),
        )

        credential.requestedMdocClaims.shouldBeEmpty()
    }

    test("json representations keep their pointers in DCQL") {
        val pointer = DCQLClaimsPathPointer(AtomicAttribute2023.isoNamespace, CLAIM_GIVEN_NAME, "nested")
        val builder = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(pointer),
            )
        )

        val query = builder.toDCQLRequest().dcqlQuery

        query.credentials.shouldBeSingleton().first().shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first().shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path shouldBe pointer
    }

    "conversion to RequestedCredential" - {
        test("VC-JWT attribute paths are prefixed with credentialSubject") {
            val options = RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = PLAIN_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer("given_name")),
            )

            val requested = options.toRequestedCredential()

            requested.shouldBeInstanceOf<RequestedCredential.VcJwt>().claims shouldBe
                    ClaimSelection.All(setOf(JsonClaimReference("credentialSubject", "given_name")))
        }

        test("optional attribute paths are requested if available, unless also required") {
            val options = RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = SD_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer("given_name")),
                optionalAttributePaths = setOf(DCQLClaimsPathPointer("given_name"), DCQLClaimsPathPointer("email")),
            )

            val requested = options.toRequestedCredential()

            requested.shouldBeInstanceOf<RequestedCredential.SdJwt>().claims shouldBe ClaimSelection.All(
                required = setOf(JsonClaimReference("given_name")),
                ifAvailable = setOf(JsonClaimReference("email")),
            )
        }

        test("a VC-JWT claim both required and optional is required, however its paths name it") {
            val options = RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = PLAIN_JWT,
                attributePaths = setOf(DCQLClaimsPathPointer("given_name")),
                optionalAttributePaths = setOf(
                    DCQLClaimsPathPointer("credentialSubject", "given_name"),
                    DCQLClaimsPathPointer("family_name"),
                ),
            )

            val requested = options.toRequestedCredential()

            requested.shouldBeInstanceOf<RequestedCredential.VcJwt>().claims shouldBe ClaimSelection.All(
                required = setOf(JsonClaimReference("credentialSubject", "given_name")),
                ifAvailable = setOf(JsonClaimReference("credentialSubject", "family_name")),
            )
        }

        test("ISO attribute paths are data elements, in the name space of the scheme or an explicit one") {
            val options = RequestOptionsCredential(
                credentialScheme = AtomicAttribute2023,
                representation = ISO_MDOC,
                attributePaths = setOf(
                    DCQLClaimsPathPointer("given_name"),
                    DCQLClaimsPathPointer("org.iso.18013.5.1", "family_name"),
                ),
            )

            val requested = options.toRequestedCredential()

            requested.shouldBeInstanceOf<RequestedCredential.Mdoc>().claims shouldBe ClaimSelection.All(
                setOf(
                    MdocClaimReference(AtomicAttribute2023.isoNamespace, "given_name"),
                    MdocClaimReference("org.iso.18013.5.1", "family_name"),
                )
            )
        }

        test("an ISO DocRequest needs only the ISO document type of the scheme, as the conversion does") {
            val scheme = object : CredentialScheme {
                override val isoDocType: String
                    get() = "org.example.document"
                override val isoNamespace: String
                    get() = "org.example"
            }
            val options = RequestOptionsCredential(
                credentialScheme = scheme,
                representation = ISO_MDOC,
                attributePaths = setOf(DCQLClaimsPathPointer("element")),
            )

            val docRequest = options.toDocRequest()

            docRequest.itemsRequest.value.apply {
                docType shouldBe "org.example.document"
                namespaces.keys shouldBe setOf("org.example")
            }
        }

        test("a scheme without the type identifier of the representation is rejected") {
            val options = RequestOptionsCredential(
                credentialScheme = SdJwtFallbackCredentialScheme("urn:example:vct"),
                representation = PLAIN_JWT,
            )

            val result = runCatching { options.toRequestedCredential() }

            result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }

        test("a collection of request options builds the same request as varargs") {
            val first = RequestOptionsCredential(AtomicAttribute2023, SD_JWT, id = "first")
            val second = RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC, id = "second")
            val expected = CredentialPresentationRequestBuilder(first, second).presentation

            val builder = CredentialPresentationRequestBuilder.fromRequestOptions(listOf(first, second))

            builder.presentation shouldBe expected
        }
    }
}
