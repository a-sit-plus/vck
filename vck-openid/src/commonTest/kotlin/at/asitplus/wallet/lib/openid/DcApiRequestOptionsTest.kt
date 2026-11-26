package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.data.ConstantIndex
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

val DcApiRequestOptionsTest by matrixSuite {
    val presentation = RequestedPresentation.allOf(
        RequestedCredential.SdJwt(ConstantIndex.AtomicAttribute2023, id = "pid")
    )
    val dcqlRequest = CredentialPresentationRequestBuilder(presentation).toDCQLRequest()
    val jwt = "eyJhbGciOiJFUzI1NiJ9.e30.c2lnbmF0dXJl"
    val cwt = byteArrayOf(0xD2.toByte(), 0x84.toByte(), 0x40, 0xA0.toByte(), 0xF6.toByte(), 0x40)

    test("constructed from a RequestedPresentation, it requests it typed, with every other parameter") {
        val transactionData = QCertCreationAcceptance(
            qcTermsConditionsUri = "https://example.com/terms",
            qcHash = byteArrayOf(1, 2, 3),
            qcHashAlgorithmOid = ObjectIdentifier("1.2.3.4"),
            credentialIds = setOf("pid"),
        )
        val expected = DcApiRequestOptions(
            presentationRequest = DcApiPresentationRequest.Typed(presentation),
            // each other than its default, so that a parameter not passed on would show
            state = "state",
            expectedOrigins = listOf("https://example.com"),
            responseMode = OpenIdConstants.ResponseMode.DcApi,
            transactionData = listOf(transactionData),
            verifierMetadataMode = VerifierMetadataMode.OMIT_IF_OUT_OF_BAND,
            registrationCertificate = RelyingPartyRegistrationCertificate(jwt = jwt),
        )

        val options = DcApiRequestOptions(
            requestedPresentation = presentation,
            state = "state",
            expectedOrigins = listOf("https://example.com"),
            responseMode = OpenIdConstants.ResponseMode.DcApi,
            transactionData = listOf(transactionData),
            verifierMetadataMode = VerifierMetadataMode.OMIT_IF_OUT_OF_BAND,
            registrationCertificate = RelyingPartyRegistrationCertificate(jwt = jwt),
        )

        options shouldBe expected
    }

    test("a response mode other than dc_api or dc_api.jwt is rejected") {
        shouldThrowAny {
            DcApiRequestOptions(presentation, responseMode = OpenIdConstants.ResponseMode.DirectPost)
        }
    }

    "from OpenId4VpRequestOptions" - {
        test("keeps the raw request and the parameters of the DC API") {
            val options = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApiJwt,
                state = "state",
                expectedOrigins = listOf("https://example.com"),
                verifierMetadataMode = VerifierMetadataMode.AUTO,
            )

            val dcApiOptions = DcApiRequestOptions.from(options)

            dcApiOptions shouldBe DcApiRequestOptions(
                presentationRequest = DcApiPresentationRequest.Raw(dcqlRequest),
                state = "state",
                expectedOrigins = listOf("https://example.com"),
                responseMode = OpenIdConstants.ResponseMode.DcApiJwt,
            )
        }

        test("moves the WRPRC of euWrprc and of verifier_info into the registration certificate") {
            @Suppress("DEPRECATION")
            val options = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://example.com"),
                verifierInfo = nonEmptyListOf(VerifierInfo(REGISTRATION_CERT_FORMAT, jwt)),
                euWrprc = cwt,
            )

            val dcApiOptions = DcApiRequestOptions.from(options)

            dcApiOptions.registrationCertificate shouldBe RelyingPartyRegistrationCertificate(jwt = jwt, cwt = cwt)
        }

        test("reads a registration_cert given as the base64url encoding of its JWT") {
            @Suppress("DEPRECATION")
            val options = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://example.com"),
                verifierInfo = nonEmptyListOf(
                    VerifierInfo(REGISTRATION_CERT_FORMAT, jwt.encodeToByteArray().encodeToString(Base64UrlStrict))
                ),
            )

            val dcApiOptions = DcApiRequestOptions.from(options)

            dcApiOptions.registrationCertificate shouldBe RelyingPartyRegistrationCertificate(jwt = jwt)
        }

        "rejects options invalid for the DC API" - {
            @Suppress("DEPRECATION")
            listOf(
                "a response mode of another channel" to OpenId4VpRequestOptions(
                    presentationRequest = dcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DirectPost,
                    responseUrl = "https://example.com/response",
                ),
                "a response URL" to OpenId4VpRequestOptions(
                    presentationRequest = dcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    responseUrl = "https://example.com/response",
                    expectedOrigins = listOf("https://example.com"),
                ),
                "another response type" to OpenId4VpRequestOptions(
                    presentationRequest = dcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    responseType = "vp_token id_token",
                    expectedOrigins = listOf("https://example.com"),
                ),
                "verifier_info of another format" to OpenId4VpRequestOptions(
                    presentationRequest = dcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf("https://example.com"),
                    verifierInfo = nonEmptyListOf(VerifierInfo("jwt", jwt)),
                ),
            ).forEach { (name, options) ->
                test(name) {
                    shouldThrowAny { DcApiRequestOptions.from(options) }
                }
            }
        }
    }
}
