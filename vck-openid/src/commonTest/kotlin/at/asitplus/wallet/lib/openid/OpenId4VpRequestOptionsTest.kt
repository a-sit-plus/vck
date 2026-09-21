package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.assertions.throwables.shouldThrowAny


val OpenId4VpRequestOptionsTest by matrixSuite {

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

        val requestBuilder = CredentialPresentationRequestBuilder(credential)
        listOf(
            requestBuilder.toDCQLRequest(),
            requestBuilder.toDCQLRequest()
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
        @Suppress("DEPRECATION")
        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                ).toPresentationExchangeRequest(),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://wallet.example")
            )
        }

        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
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
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.Fragment,
                populateClientId = false
            )
        }
    }

    test("omitting verifier metadata is rejected for encrypted response modes") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
                verifierMetadataMode = VerifierMetadataMode.OMIT_IF_OUT_OF_BAND,
            )
        }
    }
}
