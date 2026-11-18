package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf


val OpenId4VpRequestOptionsTest by matrixSuite {

    test("transaction data requires matching credential ids") {
        val credential = RequestedCredential.VcJwt(
            scheme = ConstantIndex.AtomicAttribute2023,
            id = "cred-1",
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

    test("transaction data may reference only the credentials that authorize it") {
        val pid = RequestedCredential.SdJwt(ConstantIndex.AtomicAttribute2023, id = "pid")
        val loyalty = RequestedCredential.VcJwt(ConstantIndex.AtomicAttribute2023, id = "loyalty")
        val presentationRequest = CredentialPresentationRequestBuilder(pid, loyalty).toDCQLRequest()
        val transactionData = QCertCreationAcceptance(
            qcTermsConditionsUri = "https://example.com/terms",
            qcHash = byteArrayOf(1, 2, 3),
            qcHashAlgorithmOid = ObjectIdentifier("1.2.3.4"),
            credentialIds = setOf("pid"),
        )

        val options = OpenId4VpRequestOptions(
            presentationRequest = presentationRequest,
            transactionData = listOf(transactionData),
        )

        options.transactionData shouldBe listOf(transactionData)
    }

    test("transaction data without credential ids is rejected, also next to other transaction data") {
        val pid = RequestedCredential.SdJwt(ConstantIndex.AtomicAttribute2023, id = "pid")
        val presentationRequest = CredentialPresentationRequestBuilder(pid).toDCQLRequest()
        fun transactionData(credentialIds: Set<String>) = QCertCreationAcceptance(
            qcTermsConditionsUri = "https://example.com/terms",
            qcHash = byteArrayOf(1, 2, 3),
            qcHashAlgorithmOid = ObjectIdentifier("1.2.3.4"),
            credentialIds = credentialIds,
        )

        val result = runCatching {
            OpenId4VpRequestOptions(
                presentationRequest = presentationRequest,
                transactionData = listOf(transactionData(setOf("pid")), transactionData(setOf())),
            )
        }

        result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
    }

    test("dc api requires dcql and expected origins") {
        shouldThrowAny {
            OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestedCredential.VcJwt(ConstantIndex.AtomicAttribute2023)
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
                    RequestedCredential.VcJwt(ConstantIndex.AtomicAttribute2023)
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
                    RequestedCredential.VcJwt(ConstantIndex.AtomicAttribute2023)
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DirectPostJwt,
                responseUrl = "https://example.com/response",
                verifierMetadataMode = VerifierMetadataMode.OMIT_IF_OUT_OF_BAND,
            )
        }
    }
}
