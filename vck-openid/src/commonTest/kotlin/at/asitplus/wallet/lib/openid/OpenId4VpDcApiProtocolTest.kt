package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.OpenId4VpResponseMultiSigned
import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsFlattened
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf

@Suppress("unused")
val OpenId4VpDcApiProtocolTest by testSuite {

    val callingOrigin = "https://example.com"
    val callingPackageName = "com.example.app"
    val credentialId = "credential-1"

    val dcqlRequest = CredentialPresentationRequestBuilder(
        credentials = setOf(RequestOptionsCredential(AtomicAttribute2023, SD_JWT)),
    ).toDCQLRequest()

    withFixtureGenerator(suspend {
        val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
        val holderAgent: Holder = HolderAgent(holderKeyMaterial).also { agent ->
            agent.storeCredential(
                IssuerAgent(
                    identifier = "https://issuer.example.com/".toUri(),
                    randomSource = RandomSource.Default,
                ).issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        SD_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )
        }
        object {
            val holderAgent: Holder = holderAgent
            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                keyMaterial = holderKeyMaterial,
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val clientId: String = "dc-api-rp-${uuid4()}"
            val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = EphemeralKeyWithoutCert(),
                clientIdScheme = ClientIdScheme.PreRegistered(
                    clientId = clientId,
                    redirectUri = "https://example.com/callback",
                ),
            )
        }
    }) - {

        test("DC API unsigned: parsed as DcApiUnsigned, validates and responds with OpenId4VpResponseUnsigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
                populateClientId = false,
            )
            val authnRequest = f.verifierOid4vp.createAuthnRequest(reqOptions)

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = authnRequest,
                jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
            preparationState.request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiUnsigned>()
                .callingOrigin shouldBe callingOrigin

            val response = f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()

            response.shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseUnsigned>()
        }

        test("DC API signed: parsed as DcApiSigned, validates and responds with OpenId4VpResponseSigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.verifierOid4vp.createAuthnRequestAsSignedRequestObject(reqOptions).getOrThrow()

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                verified = false,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
            preparationState.request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiSigned>()
                .callingOrigin shouldBe callingOrigin

            val response = f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()

            response.shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseSigned>()
        }

        test("DC API multisigned: parsed as DcApiMultiSigned, validates and responds with OpenId4VpResponseMultiSigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.verifierOid4vp.createAuthnRequestAsSignedRequestObject(reqOptions).getOrThrow()

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped<AuthenticationRequestParameters>(listOf(signedRequest.jws.toJwsFlattened())),
                verified = false,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
            preparationState.request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiMultiSigned>()
                .callingOrigin shouldBe callingOrigin

            val response = f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()

            response.shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseMultiSigned>()
        }

        test("DC API multisigned: origin mismatch rejects with InvalidRequest when expected_origins is set") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.verifierOid4vp.createAuthnRequestAsSignedRequestObject(reqOptions).getOrThrow()

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped<AuthenticationRequestParameters>(listOf(signedRequest.jws.toJwsFlattened())),
                verified = false,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = "https://evil.example.com",  // does not match expectedOrigins
            )

            val result = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest)
            result.isFailure shouldBe true
            result.exceptionOrNull()!!.message!! shouldContain "expected_origins"
        }

        test("DC API signed: origin mismatch rejects with InvalidRequest when expected_origins is set") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.verifierOid4vp.createAuthnRequestAsSignedRequestObject(reqOptions).getOrThrow()

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                verified = false,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = "https://evil.example.com",  // does not match expectedOrigins
            )

            val result = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest)
            result.isFailure shouldBe true
            result.exceptionOrNull()!!.message!! shouldContain "expected_origins"
        }
    }
}
