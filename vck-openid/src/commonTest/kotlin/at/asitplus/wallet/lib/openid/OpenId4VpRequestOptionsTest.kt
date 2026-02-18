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

        val requestBuilder = CredentialPresentationRequestBuilder(setOf(credential))
        listOf(
            requestBuilder.toDCQLRequest(),
            requestBuilder.toPresentationExchangeRequest()
        ).forEach {
            shouldThrowAny {
                OpenId4VpRequestOptions(
                    presentationRequest = it,
                    transactionData = listOf(transactionData)
                )
            }
        }
    }

    test("dc api requires dcql and expected origins") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023))
                ).toPresentationExchangeRequest(),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://wallet.example")
            )
        }

        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023))
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = null
            )
        }
    }

    test("non dc api requires client id population") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    setOf(RequestOptionsCredential(ConstantIndex.AtomicAttribute2023))
                ).toPresentationExchangeRequest(),
                responseMode = OpenIdConstants.ResponseMode.Fragment,
                populateClientId = false
            )
        }
    }
}
