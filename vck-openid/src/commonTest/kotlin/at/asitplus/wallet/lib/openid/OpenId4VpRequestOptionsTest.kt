package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.string.shouldContain
import io.ktor.http.Url


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

    test("presentation exchange is rejected for every OpenID transport") {
        @Suppress("DEPRECATION")
        val presentationExchange = CredentialPresentationRequestBuilder(
            RequestOptionsCredential(ConstantIndex.AtomicAttribute2023)
        ).toPresentationExchangeRequest()

        listOf(
            OpenIdConstants.ResponseMode.Fragment,
            OpenIdConstants.ResponseMode.DirectPost,
            OpenIdConstants.ResponseMode.DirectPostJwt,
            OpenIdConstants.ResponseMode.DcApi,
            OpenIdConstants.ResponseMode.DcApiJwt,
        ).forEach { responseMode ->
            shouldThrowAny {
                OpenId4VpRequestOptions(
                    presentationRequest = presentationExchange,
                    responseMode = responseMode,
                    responseUrl = "https://example.com/response",
                    expectedOrigins = listOf("https://wallet.example"),
                )
            }
        }
    }

    test("incoming presentation definitions are rejected explicitly") {
        @Suppress("DEPRECATION")
        val definitions = listOf(
            AuthenticationRequestParameters(
                presentationDefinition = PresentationDefinition(DifInputDescriptor(id = "legacy"))
            ),
            AuthenticationRequestParameters(presentationDefinitionUrl = "https://example.com/pd.json"),
        )
        val holder = OpenId4VpHolder()

        definitions.forEach { parameters ->
            holder.startAuthorizationResponsePreparation(
                RequestParametersFrom.Uri(Url("https://wallet.example/request"), parameters)
            ).exceptionOrNull()?.message shouldContain "presentation_definition"
        }
    }

    test("manually supplied presentation exchange cannot bypass OpenID finalization") {
        @Suppress("DEPRECATION")
        val legacyRequest = CredentialPresentationRequest.PresentationExchangeRequest(
            PresentationDefinition(DifInputDescriptor(id = "legacy"))
        )
        val parameters = AuthenticationRequestParameters(
            responseType = OpenIdConstants.VP_TOKEN,
            clientId = "https://verifier.example",
            redirectUrl = "https://verifier.example/callback",
            nonce = "nonce",
            state = "state",
        )
        val request = RequestParametersFrom.Uri(Url("https://wallet.example/request"), parameters)
        val preparationState = AuthorizationResponsePreparationState(
            request = request,
            credentialPresentationRequest = null,
            clientMetadata = null,
            jsonWebKeys = null,
            verifierInfo = null,
            audience = "https://verifier.example",
        )
        @Suppress("DEPRECATION")
        val presentation = CredentialPresentation.PresentationExchangePresentation(legacyRequest)

        val result = OpenId4VpHolder()
            .finalizeAuthorizationResponse(preparationState, presentation)
            .getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

        result.error?.error shouldBe OpenIdConstants.Errors.INVALID_REQUEST
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
