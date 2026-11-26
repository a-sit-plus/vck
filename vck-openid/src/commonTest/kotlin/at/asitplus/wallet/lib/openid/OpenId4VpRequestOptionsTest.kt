package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString


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

    "credential ids of verifier info" - {
        val presentationRequest = CredentialPresentationRequestBuilder(
            RequestedCredential.SdJwt(ConstantIndex.AtomicAttribute2023, id = "pid")
        ).toDCQLRequest()
        fun verifierInfo(credentialIds: Set<String>?) =
            VerifierInfo(format = "jwt", data = "eyJhbGciOiJFUzI1NiJ9", credentialIds = credentialIds)

        listOf(setOf("pid"), null).forEach { credentialIds ->
            test("$credentialIds are accepted") {
                val info = nonEmptyListOf(verifierInfo(credentialIds))

                val result = runCatching { OpenId4VpRequestOptions(presentationRequest, verifierInfo = info) }

                result.isSuccess shouldBe true
            }
        }

        listOf(setOf("unknown"), setOf()).forEach { credentialIds ->
            test("$credentialIds are rejected") {
                val info = nonEmptyListOf(verifierInfo(credentialIds))

                val result = runCatching { OpenId4VpRequestOptions(presentationRequest, verifierInfo = info) }

                result.exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
            }
        }
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

    "registration certificate" - {
        val presentationRequest = CredentialPresentationRequestBuilder(
            RequestedCredential.SdJwt(ConstantIndex.AtomicAttribute2023)
        ).toDCQLRequest()
        val jwt = "eyJhbGciOiJFUzI1NiJ9.e30.c2lnbmF0dXJl"
        val cwt = byteArrayOf(0xD2.toByte(), 0x84.toByte(), 0x40, 0xA0.toByte(), 0xF6.toByte(), 0x40)

        test("needs its JWT or its CWT") {
            shouldThrowAny { RelyingPartyRegistrationCertificate() }
        }

        test("is sent in verifier_info as the base64url encoding of its JWT") {
            val registrationCertificate = RelyingPartyRegistrationCertificate(jwt = jwt)

            val verifierInfo = registrationCertificate.verifierInfo

            verifierInfo shouldBe VerifierInfo(
                format = OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT,
                data = jwt.encodeToByteArray().encodeToString(Base64UrlStrict),
            )
        }

        test("is rejected next to a registration_cert in verifierInfo") {
            shouldThrowAny {
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    verifierInfo = nonEmptyListOf(
                        VerifierInfo(OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT, jwt)
                    ),
                    registrationCertificate = RelyingPartyRegistrationCertificate(jwt = jwt),
                )
            }
        }

        test("is rejected with its CWT next to euWrprc") {
            shouldThrowAny {
                @Suppress("DEPRECATION")
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf("https://example.com"),
                    euWrprc = cwt,
                    registrationCertificate = RelyingPartyRegistrationCertificate(cwt = cwt),
                )
            }
        }

        test("is rejected without its JWT for an OpenID4VP request outside of the DC API") {
            shouldThrowAny {
                OpenId4VpRequestOptions(
                    presentationRequest = presentationRequest,
                    registrationCertificate = RelyingPartyRegistrationCertificate(cwt = cwt),
                )
            }
        }
    }
}
