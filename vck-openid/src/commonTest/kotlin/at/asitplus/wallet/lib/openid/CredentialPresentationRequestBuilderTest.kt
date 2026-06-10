package at.asitplus.wallet.lib.openid

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf


val CredentialPresentationRequestBuilderTest by matrixSuite {
    test("invalid credential scheme for SD-JWT should not throw when creating query") {
        val credential = RequestOptionsCredential(
            credentialScheme = object : ConstantIndex.CredentialScheme {
                override val schemaUri: String = "https://example.com"
            },
            representation = ConstantIndex.CredentialRepresentation.SD_JWT
        )

        CredentialPresentationRequestBuilder(
            setOf(credential)
        ).apply {
            toDCQLRequest()
            toPresentationExchangeRequest()
        }
    }

    test("invalid credential scheme for ISO should not throw when creating query") {
        val credential = RequestOptionsCredential(
            credentialScheme = object : ConstantIndex.CredentialScheme {
                override val schemaUri: String = "https://example.com"
            },
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC
        )
        CredentialPresentationRequestBuilder(setOf(credential)).apply {
            toDCQLRequest()
            toPresentationExchangeRequest()
        }
    }

    test("sd-jwt dcql mapping includes metadata and claims") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME),
                    requestedOptionalAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val credentialQuery = presentationRequest.shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()

        credentialQuery.meta.shouldBeInstanceOf<DCQLSdJwtCredentialMetadataAndValidityConstraints>()
            .vctValues shouldContain ConstantIndex.AtomicAttribute2023.sdJwtType

        val claims = credentialQuery.claims.shouldNotBeNull().toList().apply {
            size shouldBe 2
        }
        val claimNames = claims.map {
            it.shouldBeInstanceOf<DCQLJsonClaimsQuery>().path.segments.first()
                .shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
                .name
        }.toSet()

        claimNames shouldBe setOf(
            ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME,
            ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
        )
    }

    test("sd-jwt dcql mapping supports literal dot claim names with typed paths") {
        val dotClaimName = "foo.bar"
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer(dotClaimName)),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val claim = presentationRequest.shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLJsonClaimsQuery>()

        claim.path.segments.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>()
            .name shouldBe dotClaimName
    }

    test("sd-jwt dcql mapping supports nested typed paths") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer("foo", "bar")),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val segments = presentationRequest.shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments

        segments.map {
            it.shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>().name
        } shouldBe listOf("foo", "bar")
    }

    @Suppress("DEPRECATION")
    test("sd-jwt dcql mapping keeps string attributes as nested dot shorthand") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = setOf("foo.bar"),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val segments = presentationRequest.shouldNotBeNull().dcqlQuery
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLSdJwtCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLJsonClaimsQuery>()
            .path.segments

        segments.map {
            it.shouldBeInstanceOf<DCQLClaimsPathPointerSegment.NameSegment>().name
        } shouldBe listOf("foo", "bar")
    }

    test("presentation exchange mapping supports literal dot claim names with typed paths") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer("foo.bar")),
                    id = "cred-1"
                )
            ),
        ).toPresentationExchangeRequest()

        presentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.PresentationExchangeRequest>()
            .presentationDefinition.inputDescriptors.shouldBeSingleton().first()
            .shouldBeInstanceOf<DifInputDescriptor>()
            .constraints.shouldNotBeNull().fields.shouldNotBeNull()
            .map { it.path.shouldBeSingleton().first() }
            .shouldContain("$['foo.bar']")
    }

    test("presentation exchange mapping uses shorthand paths for ordinary claims") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer("given_name")),
                    id = "cred-1"
                )
            ),
        ).toPresentationExchangeRequest()

        presentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.PresentationExchangeRequest>()
            .presentationDefinition.inputDescriptors.shouldBeSingleton().first()
            .shouldBeInstanceOf<DifInputDescriptor>()
            .constraints.shouldNotBeNull().fields.shouldNotBeNull()
            .map { it.path.shouldBeSingleton().first() }
            .shouldContain("$.given_name")
    }

    test("presentation exchange mapping supports nested typed paths") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    attributePaths = setOf(DCQLClaimsPathPointer("foo", "bar")),
                    id = "cred-1"
                )
            ),
        ).toPresentationExchangeRequest()

        presentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.PresentationExchangeRequest>()
            .presentationDefinition.inputDescriptors.shouldBeSingleton().first()
            .shouldBeInstanceOf<DifInputDescriptor>()
            .constraints.shouldNotBeNull().fields.shouldNotBeNull()
            .map { it.path.shouldBeSingleton().first() }
            .shouldContain("$.foo.bar")
    }

    @Suppress("DEPRECATION")
    test("presentation exchange mapping converts string attributes to nested typed paths") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = setOf("foo.bar"),
                    id = "cred-1"
                )
            ),
        ).toPresentationExchangeRequest()

        presentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.PresentationExchangeRequest>()
            .presentationDefinition.inputDescriptors.shouldBeSingleton().first()
            .shouldBeInstanceOf<DifInputDescriptor>()
            .constraints.shouldNotBeNull().fields.shouldNotBeNull()
            .map { it.path.shouldBeSingleton().first() }
            .shouldContain("$.foo.bar")
    }


    test("iso mdoc dcql mapping includes namespace and doctype") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    requestedAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val credentialQuery = presentationRequest.shouldNotBeNull().dcqlQuery.shouldNotBeNull()
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()

        credentialQuery.meta.shouldBeInstanceOf<DCQLIsoMdocCredentialMetadataAndValidityConstraints>()
            .doctypeValue shouldBe ConstantIndex.AtomicAttribute2023.isoDocType

        val claim = credentialQuery.claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>()
        claim.namespace shouldBe ConstantIndex.AtomicAttribute2023.isoNamespace
        claim.claimName shouldBe ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
    }

    test("iso mdoc dcql mapping supports explicit namespace claim paths") {
        val namespace = "custom.namespace"
        val claimName = "custom_claim"
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    attributePaths = setOf(DCQLClaimsPathPointer(namespace, claimName)),
                    id = "cred-1"
                )
            ),
        ).toDCQLRequest()

        val claim = presentationRequest.shouldNotBeNull().dcqlQuery.shouldNotBeNull()
            .credentials.shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocCredentialQuery>()
            .claims.shouldNotBeNull().shouldBeSingleton().first()
            .shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>()

        claim.namespace shouldBe namespace
        claim.claimName shouldBe claimName
    }

    test("iso mdoc presentation exchange mapping supports explicit namespace claim paths") {
        val presentationRequest = CredentialPresentationRequestBuilder(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    attributePaths = setOf(DCQLClaimsPathPointer("custom.namespace", "custom_claim")),
                    id = "cred-1"
                )
            ),
        ).toPresentationExchangeRequest()

        presentationRequest.shouldBeInstanceOf<CredentialPresentationRequest.PresentationExchangeRequest>()
            .presentationDefinition.inputDescriptors.shouldBeSingleton().first()
            .shouldBeInstanceOf<DifInputDescriptor>()
            .constraints.shouldNotBeNull().fields.shouldNotBeNull()
            .map { it.path.shouldBeSingleton().first() }
            .shouldContain("$['custom.namespace'].custom_claim")
    }
}
