package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.dcapi.EncryptedResponseData
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.IsoSdJwtKeyBinding
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialTrustScope
import at.asitplus.wallet.lib.validation.CredentialTrustScopes
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.PresentationChecks
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import at.asitplus.wallet.lib.validation.ValidationDecision
import at.asitplus.wallet.lib.validation.ValidationPolicy
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Duration.Companion.minutes

private const val CALLING_ORIGIN = "https://example.com"

private val sdJwtCredential = RequestOptionsCredential(
    credentialScheme = AtomicAttribute2023,
    representation = SD_JWT,
    attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
)

private val mdocCredential = RequestOptionsCredential(
    credentialScheme = AtomicAttribute2023,
    representation = ISO_MDOC,
    attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
)

private fun sessionTranscriptFor(isoMdocRequest: IsoMdocRequest, origin: String) = SessionTranscript.DcApi(
    DCAPIHandover(
        type = TYPE_DCAPI,
        hash = coseCompliantSerializer.encodeToByteArray(
            DCAPIInfo(isoMdocRequest.encryptionInfo, origin.serializeOrigin()!!)
        ).sha256(),
    )
)

private val hpke = HPKE(HPKE.KEM.DHKEM_P256_HKDF_SHA256, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_128_GCM)

/** Encrypts [deviceResponse] as the wallet does for ISO/IEC 18013-7 Annex C. */
private fun sealDeviceResponse(isoMdocRequest: IsoMdocRequest, deviceResponse: DeviceResponse): DCAPIResponse {
    val sealed = hpke.SealBase(
        pkR = isoMdocRequest.encryptionInfo.encryptionParameters.recipientPublicKey
            .toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC,
        info = coseCompliantSerializer.encodeToByteArray(sessionTranscriptFor(isoMdocRequest, CALLING_ORIGIN)),
        aad = byteArrayOf(),
        pt = coseCompliantSerializer.encodeToByteArray(deviceResponse),
    )
    return DCAPIResponse(
        EncryptedResponse(TYPE_DCAPI, EncryptedResponseData(sealed.encapsulatedSecret, sealed.ciphertext))
    )
}

val Iso180137AnnexCSdJwtTest by matrixSuite {

    fixture {
        runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val issuerKey = EphemeralKeyWithSelfSignedCert()
            val issuer = IssuerAgent(
                keyMaterial = issuerKey,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holder = HolderAgent(holderKeyMaterial).also {
                issueAndStoreSdJwt(it, holderKeyMaterial, issuer)
                issueAndStoreIsoMdoc(it, holderKeyMaterial, issuer)
            }
            val readerKey = EphemeralKeyWithSelfSignedCert()
            object {
                val holder = holder

                fun verifier(authenticated: Boolean) = DcApiVerifier(
                    clientIdScheme = if (authenticated) ClientIdScheme.CertificateHash(
                        chain = listOf(runBlocking { readerKey.getCertificate()!! }),
                        redirectUri = "https://example.com/callback",
                    ) else ClientIdScheme.PreRegistered(
                        clientId = "dc-api-rp-${uuid4()}",
                        redirectUri = "https://example.com/callback",
                    ),
                    keyMaterial = if (authenticated) readerKey else EphemeralKeyWithoutCert(),
                    stateToIsoMdocRequestStore = DefaultMapStore(),
                    ephemeralEncryptionKeyService = EphemeralEncryptionKeyService(DefaultMapStore()),
                    credentialValidator = CredentialValidator(
                        trustAnchors = CredentialTrustScopes(
                            CredentialTrustScope(
                                credentialIdentifiers = setOf(AtomicAttribute2023.isoDocType, AtomicAttribute2023.sdJwtType),
                                source = "test issuer",
                                issuance = { setOfNotNull(issuerKey.getCertificate()) },
                                status = { emptySet() },
                            )
                        ),
                    ),
                    presentationPolicy = ValidationPolicy(
                        trust = TrustPolicy.RequireAuthorizedSigner,
                        status = StatusPolicy.Skip,
                        timeLeeway = 5.minutes,
                        requireTimeliness = true,
                    ),
                )

                suspend fun DcApiVerifier.isoMdocRequest(state: String, vararg credentials: RequestOptionsCredential) =
                    createAuthnRequest(
                        OpenId4VpRequestOptions(
                            presentationRequest = CredentialPresentationRequestBuilder(*credentials).toDCQLRequest()!!,
                            responseMode = OpenIdConstants.ResponseMode.DcApi,
                            expectedOrigins = listOf(CALLING_ORIGIN),
                            state = state,
                        ),
                        DcApiCreationOptions.Iso180137AnnexC,
                    ).getOrThrow().digital.requests.shouldBeSingleton().first()
                        .shouldBeInstanceOf<DigitalCredentialGetRequest.IsoMdoc>().data

                /** The wallet's device response, created with [sessionTranscript]. */
                suspend fun deviceResponse(
                    isoMdocRequest: IsoMdocRequest,
                    sessionTranscript: SessionTranscript = sessionTranscriptFor(isoMdocRequest, CALLING_ORIGIN),
                ): DeviceResponse = holder.createDefaultPresentation(
                    request = PresentationRequestParameters(
                        nonce = uuid4().toString(),
                        audience = CALLING_ORIGIN,
                        calcIsoSessionTranscript = { sessionTranscript },
                    ),
                    credentialPresentationRequest =
                        CredentialPresentationRequest.IsoDeviceRetrieval(isoMdocRequest.deviceRequest),
                ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                    .deviceResponse
            }
        }
    } - {

        test("an SD-JWT VC requested with DCQL is requested, presented, and validated over Annex C") { f ->
            with(f) {
                val verifier = verifier(authenticated = false)
                val state = uuid4().toString()
                val isoMdocRequest = verifier.isoMdocRequest(state, sdJwtCredential)
                isoMdocRequest.deviceRequest.docRequests.single().itemsRequest.value.apply {
                    docType shouldBe AtomicAttribute2023.sdJwtType
                    requestInfo.shouldNotBeNull().docFormat shouldBe DocRequestInfo.DOC_FORMAT_SD_JWT
                }

                val result = verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(isoMdocRequest, deviceResponse(isoMdocRequest)),
                    externalId = state,
                    expectedOrigin = CALLING_ORIGIN,
                ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()

                result.validationReport.decision shouldBe ValidationDecision.ACCEPTED
                result.presentationValidations.single().presentation
                    .shouldBeInstanceOf<ValidatedPresentation.SdJwt>()
                    .credential.reconstructedJsonObject[CLAIM_GIVEN_NAME].shouldNotBeNull()
                    .jsonPrimitive.content shouldBe "Susanne"
            }
        }

        test("with reader authentication, the key binding JWT is bound to the readerAuth of the request") { f ->
            with(f) {
                val verifier = verifier(authenticated = true)
                val state = uuid4().toString()
                val isoMdocRequest = verifier.isoMdocRequest(state, sdJwtCredential)
                isoMdocRequest.deviceRequest.docRequests.single().readerAuth.shouldNotBeNull()
                val deviceResponse = deviceResponse(isoMdocRequest)
                val compact = DefaultZlibService().decompress(deviceResponse.otherDocuments!!.single().data)!!
                SdJwtSigned.parseCatching(compact.decodeToString()).getOrThrow().keyBindingJws.shouldNotBeNull()
                    .payload.audience shouldNotBe IsoSdJwtKeyBinding.AUDIENCE_WITHOUT_READER_AUTHENTICATION

                verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(isoMdocRequest, deviceResponse),
                    externalId = state,
                    expectedOrigin = CALLING_ORIGIN,
                ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()
                    .validationReport.decision shouldBe ValidationDecision.ACCEPTED
            }
        }

        test("an mdoc and an SD-JWT VC are requested and validated in one response") { f ->
            with(f) {
                val verifier = verifier(authenticated = false)
                val state = uuid4().toString()
                val isoMdocRequest = verifier.isoMdocRequest(state, mdocCredential, sdJwtCredential)

                val result = verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(isoMdocRequest, deviceResponse(isoMdocRequest)),
                    externalId = state,
                    expectedOrigin = CALLING_ORIGIN,
                ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()

                result.validationReport.decision shouldBe ValidationDecision.ACCEPTED
                result.presentationValidations shouldHaveSize 2
            }
        }

        test("a key binding JWT bound to another session transcript is rejected") { f ->
            with(f) {
                val verifier = verifier(authenticated = false)
                val state = uuid4().toString()
                val isoMdocRequest = verifier.isoMdocRequest(state, sdJwtCredential)
                val otherTranscript = sessionTranscriptFor(isoMdocRequest, "https://other.example.com")

                val result = verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(isoMdocRequest, deviceResponse(isoMdocRequest, otherTranscript)),
                    externalId = state,
                    expectedOrigin = CALLING_ORIGIN,
                ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()

                result.validationReport.decision shouldBe ValidationDecision.REJECTED
                result.presentationValidations.single().report.checks.shouldBeInstanceOf<PresentationChecks>()
                    .challenge.shouldBeInstanceOf<CheckOutcome.Failed>()
            }
        }

        test("an SD-JWT VC that can not be decompressed is rejected, one for another document request fails") { f ->
            with(f) {
                val verifier = verifier(authenticated = false)
                val state = uuid4().toString()
                val isoMdocRequest = verifier.isoMdocRequest(state, sdJwtCredential)
                val deviceResponse = deviceResponse(isoMdocRequest)
                val document = deviceResponse.otherDocuments!!.single()

                verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(
                        isoMdocRequest,
                        deviceResponse.copy(otherDocuments = arrayOf(document.copy(data = byteArrayOf(1, 2, 3)))),
                    ),
                    externalId = state,
                    expectedOrigin = CALLING_ORIGIN,
                ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()
                    .validationReport.decision shouldBe ValidationDecision.REJECTED

                val otherState = uuid4().toString()
                val otherRequest = verifier.isoMdocRequest(otherState, sdJwtCredential)
                verifier.validateIsoResponse(
                    receivedData = sealDeviceResponse(
                        otherRequest,
                        deviceResponse(otherRequest).let {
                            it.copy(otherDocuments = arrayOf(it.otherDocuments!!.single().copy(docRequestIds = listOf(1U))))
                        },
                    ),
                    externalId = otherState,
                    expectedOrigin = CALLING_ORIGIN,
                ).isFailure shouldBe true
            }
        }
    }
}
