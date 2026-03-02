package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf


val CredentialPresentationRequestBuilderTest by testSuite {
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
}
