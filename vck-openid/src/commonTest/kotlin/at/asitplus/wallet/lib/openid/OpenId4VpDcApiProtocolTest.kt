package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.OpenId4VpResponseMultiSigned
import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJwsFlattened
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalMatchingResult
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

val OpenId4VpDcApiProtocolTest by matrixSuite {

    val callingOrigin = "https://example.com"
    val androidCallingOrigin = "android:apk-key-hash:AbCdEf"
    val callingPackageName = "com.example.app"
    val credentialId = "credential-1"

    val dcqlRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(AtomicAttribute2023, SD_JWT),
    ).toDCQLRequest()

    val isoMdocDcqlRequest = CredentialPresentationRequestBuilder(
        RequestOptionsCredential(
            credentialScheme = AtomicAttribute2023,
            representation = ISO_MDOC,
            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
        ),
    ).toDCQLRequest()

    fixture {
        runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val issuerAgent = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holderAgent: Holder = HolderAgent(holderKeyMaterial).also { agent ->
                issueAndStoreSdJwt(agent, holderKeyMaterial)
                issueAndStoreIsoMdoc(agent, holderKeyMaterial)
            }
            val storedCredentialIds = holderAgent.getCredentials()!!.map { it.getDcApiId() }
            object {
                val allowedOriginSchemes = OpenId4VpHolder.DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES.toMutableSet()
                val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                    keyMaterial = holderKeyMaterial,
                    holder = holderAgent,
                    randomSource = RandomSource.Default,
                    allowedDcApiOriginSchemes = { allowedOriginSchemes },
                )
                val dcApiHolder = DcApiHolder(
                    keyMaterial = holderKeyMaterial,
                    holder = holderAgent,
                    openId4VpHolder = holderOid4vp,
                )
                val dcApiVerifier = DcApiVerifier(
                    keyMaterial = EphemeralKeyWithoutCert(),
                    clientIdScheme = ClientIdScheme.PreRegistered(
                        clientId = "dc-api-rp-${uuid4()}",
                        redirectUri = "https://example.com/callback",
                    ),
                )

                /**
                 * Lets the holder answer [authnRequest] from [origin], as the browser would, so that its device
                 * signature covers the session transcript both sides derive from nonce and origin.
                 */
                suspend fun responseFor(
                    authnRequest: AuthenticationRequestParameters,
                    origin: String,
                ): OpenId4VpResponseUnsigned = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                    parameters = authnRequest,
                    jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                    credentialIds = storedCredentialIds,
                    callingPackageName = callingPackageName,
                    callingOrigin = origin,
                ).let { request ->
                    holderOid4vp.startAuthorizationResponsePreparation(request).getOrThrow()
                        .let { holderOid4vp.finalizeAuthorizationResponse(it).getOrThrow() }
                        .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                        .params.shouldBeInstanceOf<OpenId4VpResponseUnsigned>()
                }

                /** Extracts the unsigned authn request from the browser-facing [CredentialRequestOptions]. */
                suspend fun createUnsignedAuthnRequest(
                    reqOptions: OpenId4VpRequestOptions,
                ): AuthenticationRequestParameters = dcApiVerifier
                    .createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpUnsigned).getOrThrow()
                    .singleRequest<DigitalCredentialGetRequest.OpenId4VpUnsigned>()
                    .data

                /** Extracts the signed authn request from the browser-facing [CredentialRequestOptions]. */
                suspend fun createSignedAuthnRequest(
                    reqOptions: OpenId4VpRequestOptions,
                ): JwsCompactTyped<AuthenticationRequestParameters> = dcApiVerifier
                    .createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpSigned).getOrThrow()
                    .singleRequest<DigitalCredentialGetRequest.OpenId4VpSigned>()
                    .data.request
                    .typed<AuthenticationRequestParameters, JwsCompact>()

                suspend fun preparationStateFor(
                    presentationRequest: CredentialPresentationRequest?,
                ): AuthorizationResponsePreparationState {
                    val authnRequest = createUnsignedAuthnRequest(
                        OpenId4VpRequestOptions(
                            presentationRequest = dcqlRequest,
                            responseMode = OpenIdConstants.ResponseMode.DcApi,
                            expectedOrigins = listOf(callingOrigin),
                        )
                    )
                    return holderOid4vp.startAuthorizationResponsePreparation(
                        RequestParametersFrom.OpenId4VpDcApiUnsigned(
                            parameters = authnRequest,
                            jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                            credentialIds = storedCredentialIds,
                            callingPackageName = callingPackageName,
                            callingOrigin = callingOrigin,
                        )
                    ).getOrThrow().copy(credentialPresentationRequest = presentationRequest)
                }
            }
        }
    } - {

        test("createAuthnRequest rejects response modes other than DC API") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.Fragment,
            )
            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpUnsigned)
                .isFailure shouldBe true
            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpSigned)
                .isFailure shouldBe true
        }

        test("createAuthnRequest rejects encrypted response mode when metadata conveys no encryption key") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApiJwt,
                expectedOrigins = listOf(callingOrigin),
            )
            // fixture verifier uses ClientIdScheme.PreRegistered, for which no client metadata is populated
            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpUnsigned)
                .isFailure shouldBe true
            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpSigned)
                .isFailure shouldBe true
        }

        test("createAuthnRequest with encrypted response mode conveys encryption key in metadata") {
            val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val dcApiVerifier = DcApiVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateHash(
                    chain = listOf(verifierKeyMaterial.getCertificate()!!),
                    redirectUri = "https://example.com/callback",
                ),
            )
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApiJwt,
                expectedOrigins = listOf(callingOrigin),
            )

            val authnRequest = dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.OpenId4VpUnsigned)
                .getOrThrow().singleRequest<DigitalCredentialGetRequest.OpenId4VpUnsigned>()
                .data

            authnRequest.clientMetadata.shouldNotBeNull().jsonWebKeySet.shouldNotBeNull().keys.shouldBeSingleton()
        }

        test("DC API Annex C: createAuthnRequest renders the DCQL query as ISO device request") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                    ),
                ).toDCQLRequest(),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )

            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.Iso180137AnnexC)
                .getOrThrow().singleRequest<DigitalCredentialGetRequest.IsoMdoc>()
                .data.apply {
                    encryptionInfo.type shouldBe DCAPIHandover.TYPE_DCAPI
                    encryptionInfo.encryptionParameters.nonce.shouldNotBeNull()
                    deviceRequest.docRequests.single().itemsRequest.value.apply {
                        docType shouldBe AtomicAttribute2023.isoDocType
                        namespaces[AtomicAttribute2023.isoNamespace]!!.entries.single() shouldBe
                                SingleItemsRequest(CLAIM_GIVEN_NAME, false)

                    }
                }
        }


        test("DC API Annex C: createAuthnRequest renders the Device Retrieval request as ISO device request") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = CredentialPresentationRequestBuilder(
                    RequestOptionsCredential(
                        credentialScheme = AtomicAttribute2023,
                        representation = ISO_MDOC,
                        attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                    ),
                ).toIsoDeviceRetrievalRequest(),
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )

            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.Iso180137AnnexC)
                .getOrThrow().singleRequest<DigitalCredentialGetRequest.IsoMdoc>()
                .data.apply {
                    encryptionInfo.type shouldBe DCAPIHandover.TYPE_DCAPI
                    encryptionInfo.encryptionParameters.nonce.shouldNotBeNull()
                    deviceRequest.docRequests.single().itemsRequest.value.apply {
                        docType shouldBe AtomicAttribute2023.isoDocType
                        namespaces[AtomicAttribute2023.isoNamespace]!!.entries.single() shouldBe
                                SingleItemsRequest(CLAIM_GIVEN_NAME, false)
                        encryptionInfo.type shouldBe DCAPIHandover.TYPE_DCAPI
                        encryptionInfo.encryptionParameters.nonce.shouldNotBeNull()
                    }
                }
        }

        test("getMatchingCredentials matches ISO Device Retrieval requests") { f ->
            val request = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC),
            ).toIsoDeviceRetrievalRequest()

            f.holderOid4vp.getMatchingCredentials(f.preparationStateFor(request)).getOrThrow()
                .shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<*>>()
                .matchingResult.documentMatches.shouldBeSingleton().single().shouldBeSingleton()
        }

        test("getMatchingCredentials rejects requests without a credential presentation") { f ->
            f.holderOid4vp.getMatchingCredentials(f.preparationStateFor(null))
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain "presentation request"
        }

        test("createAuthnRequest combines several exchange protocols in one browser call") { f ->
            val isoDcqlRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(
                    credentialScheme = AtomicAttribute2023,
                    representation = ISO_MDOC,
                    attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
                ),
            ).toDCQLRequest()

            f.dcApiVerifier.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    presentationRequest = isoDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf(callingOrigin),
                ),
                DcApiCreationOptions.OpenId4VpUnsigned,
                DcApiCreationOptions.Iso180137AnnexC,
            ).getOrThrow().digital.requests
                .shouldHaveSize(2).shouldHaveSize(2).apply {
                    first().shouldBeInstanceOf<DigitalCredentialGetRequest.OpenId4VpUnsigned>()
                        .data.dcqlQuery shouldBe isoDcqlRequest!!.dcqlQuery
                    last().shouldBeInstanceOf<DigitalCredentialGetRequest.IsoMdoc>()
                        .data.deviceRequest.docRequests.single().itemsRequest.value.docType shouldBe
                            AtomicAttribute2023.isoDocType
                }
        }

        test("createAuthnRequest rejects empty creation options") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            f.dcApiVerifier.createAuthnRequest(reqOptions).isFailure shouldBe true
        }

        test("DC API Annex C: createAuthnRequest rejects non-mdoc DCQL queries") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest, // SD-JWT credential query
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            f.dcApiVerifier.createAuthnRequest(reqOptions, DcApiCreationOptions.Iso180137AnnexC)
                .isFailure shouldBe true
        }

        test("DC API unsigned: parsed as DcApiUnsigned, validates and responds with OpenId4VpResponseUnsigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val authnRequest = f.createUnsignedAuthnRequest(reqOptions)
            // client_id MUST be omitted in unsigned requests, per OpenID4VP 1.0 Appendix A.3.1
            authnRequest.clientId.shouldBeNull()

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = authnRequest,
                jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
                .apply {
                    request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiUnsigned>()
                        .callingOrigin shouldBe callingOrigin
                }

            f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseUnsigned>()
        }

        test("DC API holder dispatches and finalizes OpenID4VP requests") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val authnRequest = f.createUnsignedAuthnRequest(reqOptions)
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = authnRequest,
                jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val state = f.dcApiHolder.startAuthorizationResponsePreparation(dcApiRequest)
                .getOrThrow()
                .shouldBeInstanceOf<DcApiPreparationState.OpenId4Vp>()
            val response = f.dcApiHolder.finalizeAuthorizationResponse(state)
                .getOrThrow()

            response.shouldBeInstanceOf<OpenId4VpResponseUnsigned>()
        }

        test("DC API unsigned: SD-JWT response validates with origin audience") { f ->
            val rpOrigin = "https://wallet-rp.a-sit.plus"
            val transactionId = uuid4().toString()
            val authnRequest = f.createUnsignedAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = dcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    responseUrl = "$rpOrigin/transaction/result/$transactionId",
                    expectedOrigins = listOf(rpOrigin),
                    state = transactionId,
                )
            )

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiUnsigned(
                parameters = authnRequest,
                jsonString = joseCompliantSerializer.encodeToString(authnRequest),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = rpOrigin,
            )

            val response = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
                .let { f.holderOid4vp.finalizeAuthorizationResponse(it).getOrThrow() }
                .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseUnsigned>()

            val validation = f.dcApiVerifier.validateAuthnResponse(response, transactionId, rpOrigin).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult!!.getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single()

            validation.getOrThrow()
        }

        test("DC API unsigned: mdoc response validates against the DC API session transcript") { f ->
            val transactionId = uuid4().toString()
            val authnRequest = f.createUnsignedAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = isoMdocDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf(callingOrigin),
                    state = transactionId,
                )
            )

            val response = f.responseFor(authnRequest, callingOrigin)

            f.dcApiVerifier.validateAuthnResponse(response, transactionId, callingOrigin).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
                .documents.single().apply {
                    validItems.firstOrNull { it.elementIdentifier == CLAIM_GIVEN_NAME }
                        .shouldNotBeNull().elementValue shouldBe "Susanne"
                    invalidItems.shouldBeEmpty()
                }
        }

        test("DC API unsigned: mdoc device signature is bound to the calling origin") { f ->
            val transactionId = uuid4().toString()
            val authnRequest = f.createUnsignedAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = isoMdocDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf(callingOrigin),
                    state = transactionId,
                )
            )

            val response = f.responseFor(authnRequest, callingOrigin)

            // the origin is hashed into the session transcript, so claiming another one does not verify
            f.dcApiVerifier.validateAuthnResponse(response, transactionId, "https://evil.example.com").getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single()
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain
                    "deviceSignature not matching"
        }

        test("DC API unsigned: mdoc device signature is bound to the nonce of its own request") { f ->
            val answeredId = uuid4().toString()
            val answeredRequest = f.createUnsignedAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = isoMdocDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf(callingOrigin),
                    state = answeredId,
                )
            )
            val otherId = uuid4().toString()
            f.createUnsignedAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = isoMdocDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApi,
                    expectedOrigins = listOf(callingOrigin),
                    state = otherId,
                )
            )

            val response = f.responseFor(answeredRequest, callingOrigin)

            // the nonce is hashed into the session transcript, so this response does not answer the other request,
            // even though origin, client and credential are the same
            f.dcApiVerifier.validateAuthnResponse(response, otherId, callingOrigin).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single()
                .exceptionOrNull().shouldNotBeNull().message.shouldNotBeNull() shouldContain
                    "deviceSignature not matching"
        }

        test("DC API unsigned: encrypted mdoc response validates, binding the recipient key") { f ->
            // the fixture verifier uses ClientIdScheme.PreRegistered, which populates no client metadata,
            // so encryption needs a scheme that conveys the encryption key in the request
            val verifierKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val dcApiVerifier = DcApiVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.CertificateHash(
                    chain = listOf(verifierKeyMaterial.getCertificate()!!),
                    redirectUri = "https://example.com/callback",
                ),
            )
            val transactionId = uuid4().toString()
            val authnRequest = dcApiVerifier.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = isoMdocDcqlRequest,
                    responseMode = OpenIdConstants.ResponseMode.DcApiJwt,
                    expectedOrigins = listOf(callingOrigin),
                    state = transactionId,
                ),
                DcApiCreationOptions.OpenId4VpUnsigned,
            ).getOrThrow().singleRequest<DigitalCredentialGetRequest.OpenId4VpUnsigned>().data

            val response = f.responseFor(authnRequest, callingOrigin)

            // an encrypted response hashes the verifier's encryption key into the session transcript as well
            response.data.response.shouldNotBeNull().count { it == '.' } shouldBe 4

            dcApiVerifier.validateAuthnResponse(response, transactionId, callingOrigin).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
                .documents.single().validItems
                .firstOrNull { it.elementIdentifier == CLAIM_GIVEN_NAME }
                .shouldNotBeNull().elementValue shouldBe "Susanne"
        }

        test("DC API signed: parsed as DcApiSigned, validates and responds with OpenId4VpResponseSigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
                .apply {
                    request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiSigned>()
                        .callingOrigin shouldBe callingOrigin
                }

            f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseSigned>()
        }

        test("DC API signed: non-web origin validates and is used as the SD-JWT audience") { f ->
            val transactionId = uuid4().toString()
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(androidCallingOrigin),
                state = transactionId,
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = androidCallingOrigin,
            )

            val response = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
                .let { f.holderOid4vp.finalizeAuthorizationResponse(it).getOrThrow() }
                .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseSigned>()

            f.dcApiVerifier.validateAuthnResponse(response, transactionId, androidCallingOrigin).getOrThrow()
                .shouldBeInstanceOf<AuthnResponseResult>()
                .vpTokenValidationResult!!.getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values.single().single().getOrThrow()
        }

        test("DC API multisigned: parsed as DcApiMultiSigned, validates and responds with OpenId4VpResponseMultiSigned") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped<AuthenticationRequestParameters>(listOf(signedRequest.jws.toJwsFlattened())),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val preparationState = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
                .apply {
                    request.shouldBeInstanceOf<RequestParametersFrom.OpenId4VpDcApiMultiSigned>()
                        .callingOrigin shouldBe callingOrigin
                }

            f.holderOid4vp.finalizeAuthorizationResponse(preparationState).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.DcApi>()
                .params.shouldBeInstanceOf<OpenId4VpResponseMultiSigned>()
        }

        test("DC API multisigned: origin mismatch rejects with InvalidRequest when expected_origins is set") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiMultiSigned(
                jwsTyped = JwsTyped<AuthenticationRequestParameters>(listOf(signedRequest.jws.toJwsFlattened())),
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = "https://evil.example.com",  // does not match expectedOrigins
            )

            f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).apply {
                isFailure shouldBe true
                exceptionOrNull()!!.message!! shouldContain "expected_origins"
            }
        }

        test("DC API signed: origin mismatch rejects with InvalidRequest when expected_origins is set") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)

            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = "https://evil.example.com",  // does not match expectedOrigins
            )

            f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).apply {
                isFailure shouldBe true
                exceptionOrNull()!!.message!! shouldContain "expected_origins"
            }
        }

        test("DC API signed: origins are compared as exact strings") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf("https://example.com/"),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            val result = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest)

            result.isFailure shouldBe true
            result.exceptionOrNull()!!.message!! shouldContain "does not match expected_origins"
        }

        test("DC API signed: rejects a calling origin with a disallowed scheme") { f ->
            val ftpOrigin = "ftp://example.com"
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(ftpOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = ftpOrigin,
            )

            val result = f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest)

            result.isFailure shouldBe true
            result.exceptionOrNull()!!.message!! shouldContain "disallowed scheme"
        }

        test("DC API signed: accepts a scheme added to the allowlist") { f ->
            val httpOrigin = "http://localhost:8080"
            f.allowedOriginSchemes += "http"
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(httpOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = signedRequest,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = httpOrigin,
            )

            f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).getOrThrow()
        }

        test("DC API signed: rejects with InvalidRequest when expected_origins is missing") { f ->
            val reqOptions = OpenId4VpRequestOptions(
                presentationRequest = dcqlRequest,
                responseMode = OpenIdConstants.ResponseMode.DcApi,
                expectedOrigins = listOf(callingOrigin),
            )
            val signedRequest = f.createSignedAuthnRequest(reqOptions)

            // Simulate a (third-party) signed request that omits expected_origins entirely.
            val withoutExpectedOrigins = JwsTyped(
                signedRequest.jws,
                signedRequest.payload.copy(expectedOrigins = null),
            )
            val dcApiRequest = RequestParametersFrom.OpenId4VpDcApiSigned(
                jwsTyped = withoutExpectedOrigins,
                credentialIds = listOf(credentialId),
                callingPackageName = callingPackageName,
                callingOrigin = callingOrigin,
            )

            f.holderOid4vp.startAuthorizationResponsePreparation(dcApiRequest).apply {
                isFailure shouldBe true
                exceptionOrNull()!!.message!! shouldContain "expected_origins must be set"
            }
        }
    }
}

/** Extracts the single [DigitalCredentialGetRequest] of the expected protocol, as a wallet would receive it. */
private inline fun <reified T : DigitalCredentialGetRequest> CredentialRequestOptions.singleRequest(): T =
    digital.requests.shouldBeSingleton().first().shouldBeInstanceOf<T>()
