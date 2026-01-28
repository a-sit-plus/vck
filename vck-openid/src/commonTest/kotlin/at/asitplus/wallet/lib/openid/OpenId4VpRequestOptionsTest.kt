package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

@Suppress("unused")
val OpenId4VpRequestOptionsTest by testSuite {

    test("transaction data requires matching credential ids") {
        val credential = RequestOptionsCredential(
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            id = "cred-1"
        )
        val transactionData = QCertCreationAcceptance(
            qcTermsConditionsUri = "https://example.com/terms",
            qcHash = byteArrayOf(1, 2, 3),
            qcHashAlgorithmOid = ObjectIdentifier("1.2.3.4"),
            credentialIds = setOf("cred-2")
        )

        shouldThrowAny {
            OpenId4VpRequestOptions(
                credentials = setOf(credential),
                transactionData = listOf(transactionData)
            )
        }
    }

    test("dc api requires dcql and expected origins") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                presentationMechanism = PresentationMechanismEnum.PresentationExchange,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://wallet.example")
            )
        }

        shouldThrowAny {
            OpenId4VpRequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                presentationMechanism = PresentationMechanismEnum.DCQL,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = null
            )
        }
    }

    test("non dc api requires client id population") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                credentials = setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)),
                responseMode = OpenIdConstants.ResponseMode.Fragment,
                populateClientId = false
            )
        }
    }

    test("sd-jwt dcql mapping includes metadata and claims") {
        val options = OpenId4VpRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    requestedAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME),
                    requestedOptionalAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME),
                    id = "cred-1"
                )
            ),
            presentationMechanism = PresentationMechanismEnum.DCQL
        )

        val query = options.toDCQLQuery().shouldNotBeNull()
        val credentialQuery = query.credentials.first()
            .shouldBeInstanceOf<at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery>()

        credentialQuery.meta.shouldBeInstanceOf<DCQLSdJwtCredentialMetadataAndValidityConstraints>()
            .vctValues shouldContain ConstantIndex.AtomicAttribute2023.sdJwtType

        val claims = credentialQuery.claims.shouldNotBeNull().toList()
        claims.size shouldBe 2
        val claimNames = claims.map {
            it.shouldBeInstanceOf<DCQLJsonClaimsQuery>().path.segments.first()
                .shouldBeInstanceOf<at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment.NameSegment>()
                .name
        }.toSet()
        claimNames shouldBe setOf(
            ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME,
            ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
        )
    }

    test("iso mdoc dcql mapping includes namespace and doctype") {
        val options = OpenId4VpRequestOptions(
            credentials = setOf(
                RequestOptionsCredential(
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    requestedAttributes = setOf(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME),
                    id = "cred-1"
                )
            ),
            presentationMechanism = PresentationMechanismEnum.DCQL
        )

        val query = options.toDCQLQuery().shouldNotBeNull()
        val credentialQuery = query.credentials.first()
            .shouldBeInstanceOf<at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery>()

        credentialQuery.meta.shouldBeInstanceOf<DCQLIsoMdocCredentialMetadataAndValidityConstraints>()
            .doctypeValue shouldBe ConstantIndex.AtomicAttribute2023.isoDocType

        val claim = credentialQuery.claims.shouldNotBeNull().first()
            .shouldBeInstanceOf<DCQLIsoMdocClaimsQuery>()
        claim.namespace shouldBe ConstantIndex.AtomicAttribute2023.isoNamespace
        claim.claimName shouldBe ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
    }
}
