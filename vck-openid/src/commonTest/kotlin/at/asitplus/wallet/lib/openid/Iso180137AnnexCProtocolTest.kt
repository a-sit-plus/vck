package at.asitplus.wallet.lib.openid

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.EncryptedResponse
import at.asitplus.dcapi.EncryptedResponseData
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray

/**
 * Tests [DcApiVerifier] against a simulated wallet performing an ISO/IEC 18013-7 Annex C
 * presentation over the Digital Credentials API, analogous to [OpenId4VpDcApiProtocolTest].
 */
val Iso180137AnnexCProtocolTest by matrixSuite {

    val callingOrigin = "https://example.com"

    val requestedCredential = RequestOptionsCredential(
        credentialScheme = AtomicAttribute2023,
        representation = ISO_MDOC,
        attributePaths = setOf(
            DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
            DCQLClaimsPathPointer(CLAIM_DATE_OF_BIRTH),
        ),
    )
    val deviceRequest = CredentialPresentationRequestBuilder(requestedCredential).toIsoDeviceRetrievalRequest()

    fixture {
        runBlocking {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default,
            )
            val holderAgent = HolderAgent(holderKeyMaterial).also { agent ->
                issueAndStoreIsoMdoc(agent, holderKeyMaterial, issuer)
            }
            object {
                val decryptionKeyMaterial = EphemeralKeyWithoutCert()
                val stateToIsoMdocRequestStore = DefaultMapStore<String, IsoMdocRequest>()
                val verifier = DcApiVerifier(
                    clientIdScheme = ClientIdScheme.PreRegistered(
                        clientId = "dc-api-rp-${uuid4()}",
                        redirectUri = "https://example.com/callback",
                    ),
                    stateToIsoMdocRequestStore = stateToIsoMdocRequestStore,
                    decryptionKeyMaterial = decryptionKeyMaterial,
                )

                /** Extracts the Annex C request from the browser-facing [CredentialRequestOptions]. */
                suspend fun createIsoMdocRequest(transactionId: String): IsoMdocRequest = verifier
                    .createAuthnRequest(
                        OpenId4VpRequestOptions(
                            presentationRequest = deviceRequest,
                            responseMode = OpenIdConstants.ResponseMode.DcApi,
                            expectedOrigins = listOf(callingOrigin),
                            state = transactionId,
                        ),
                        DcApiCreationOptions.Iso180137AnnexC,
                    ).getOrThrow()
                    .digital.requests.shouldBeSingleton().first()
                    .shouldBeInstanceOf<DigitalCredentialGetRequest.IsoMdoc>()
                    .data

                suspend fun walletResponse(
                    isoMdocRequest: IsoMdocRequest,
                    origin: String = callingOrigin,
                ) = createWalletResponse(holderAgent, holderKeyMaterial, isoMdocRequest, origin, requestedCredential)
            }
        }
    } - {

        test("createAuthnRequest renders device request and encryption info, and remembers the request") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId).apply {
                deviceRequest.deviceRequest.docRequests.shouldBeSingleton().first().itemsRequest.value.apply {
                    docType shouldBe AtomicAttribute2023.isoDocType
                    namespaces[AtomicAttribute2023.isoNamespace]!!.entries shouldBe listOf(
                        SingleItemsRequest(CLAIM_GIVEN_NAME, false),
                        SingleItemsRequest(CLAIM_DATE_OF_BIRTH, false),
                    )
                }
                encryptionInfo.type shouldBe TYPE_DCAPI
                encryptionInfo.encryptionParameters.nonce.shouldNotBeNull()
                encryptionInfo.encryptionParameters.recipientPublicKey shouldBe
                        f.decryptionKeyMaterial.publicKey.toCoseKey().getOrThrow()
            }

            f.stateToIsoMdocRequestStore.get(transactionId) shouldBe isoMdocRequest
        }

        test("Annex C walk-through: wallet response validates and contains requested claims") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            val result = f.verifier.validateIsoResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).getOrThrow()

            result.documents.shouldBeSingleton().first().apply {
                validItems.firstOrNull { it.elementIdentifier == CLAIM_GIVEN_NAME }
                    .shouldNotBeNull().elementValue shouldBe "Susanne"
                validItems.firstOrNull { it.elementIdentifier == CLAIM_DATE_OF_BIRTH }
                    .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
                invalidItems shouldBe emptyList()
            }
        }

        test("public API forwards the expected origin for Annex C") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            f.verifier.validateAuthnResponse(
                input = IsoMdocResponse(f.walletResponse(isoMdocRequest)),
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()
        }

        test("mixed-case configured host matches the browser's lowercase origin") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            f.verifier.validateAuthnResponse(
                input = IsoMdocResponse(
                    f.walletResponse(isoMdocRequest, "https://macbook-air.local:8443")
                ),
                externalId = transactionId,
                expectedOrigin = "https://MacBook-Air.local:8443",
            ).getOrThrow().shouldBeInstanceOf<Iso180137AnnexCWrapper>()
        }

        test("origin mismatch: session transcript differs, device signature verification fails") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            f.verifier.validateIsoResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = "https://evil.example.com",
            ).isFailure shouldBe true
        }

        test("wallet responding to a different encryption info fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)
            // wallet answers a request with the same decryption key, but a different nonce,
            // i.e. its session transcript is not the one the verifier will calculate
            val otherRequest = isoMdocRequest.copy(
                encryptionInfo = isoMdocRequest.encryptionInfo.copy(
                    encryptionParameters = isoMdocRequest.encryptionInfo.encryptionParameters.copy(
                        nonce = ByteArray(16) { it.toByte() }
                    )
                )
            )

            val dcApiResponse = f.walletResponse(otherRequest)

            f.verifier.validateIsoResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }

        test("response with a document of a different docType than requested fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)
            // same encryption info (so decryption and device signature verification succeed),
            // but the stored request asks for a different docType than the wallet presents
            f.stateToIsoMdocRequestStore.put(
                transactionId,
                isoMdocRequest.copy(
                    deviceRequest = DeviceRequest(
                        parsedVersion = Version(1, 0),
                        docRequests = arrayOf(
                            DocRequest(ByteStringWrapper(ItemsRequest("org.iso.18013.5.1.mDL", emptyMap())))
                        ),
                    )
                )
            )

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            f.verifier.validateIsoResponse(
                receivedData = dcApiResponse,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }

        test("unknown transaction id fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)

            f.verifier.validateIsoResponse(
                receivedData = dcApiResponse,
                externalId = "unknown-${uuid4()}",
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }

        test("tampered ciphertext fails validation") { f ->
            val transactionId = uuid4().toString()
            val isoMdocRequest = f.createIsoMdocRequest(transactionId)

            val dcApiResponse = f.walletResponse(isoMdocRequest)
            val tampered = dcApiResponse.response.encryptedResponseData.cipherText
                .also { it[0] = (it[0].toInt() xor 0x01).toByte() }
                .let {
                    DCAPIResponse(
                        EncryptedResponse(
                            TYPE_DCAPI,
                            EncryptedResponseData(dcApiResponse.response.encryptedResponseData.enc, it)
                        )
                    )
                }

            f.verifier.validateIsoResponse(
                receivedData = tampered,
                externalId = transactionId,
                expectedOrigin = callingOrigin,
            ).isFailure shouldBe true
        }
    }
}

/**
 * Simulates the wallet: computes the Annex C session transcript from the received [isoMdocRequest]
 * and its own [origin], creates a device response with the device signature over that transcript,
 * and encrypts it to the verifier's public key from the encryption info.
 */
private suspend fun createWalletResponse(
    holder: Holder,
    holderKeyMaterial: KeyMaterial,
    isoMdocRequest: IsoMdocRequest,
    origin: String,
    requestedCredential: RequestOptionsCredential,
): DCAPIResponse {
    val sessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray(
                DCAPIInfo(isoMdocRequest.encryptionInfo, origin.serializeOrigin()!!)
            ).sha256(),
        )
    )
    val signer = SignCoseDetached<ByteArray>(keyMaterial = holderKeyMaterial)
    val calcIsoSessionTranscript = { sessionTranscript }
    val deviceResponse = holder.createDefaultPresentation(
        request = PresentationRequestParameters(
            nonce = uuid4().toString(), // not relevant for mdoc device authentication
            audience = origin,
            calcIsoSessionTranscript = calcIsoSessionTranscript,
            calcIsoDeviceSignaturePlain = { input ->
                signer(
                    protectedHeader = null,
                    unprotectedHeader = null,
                    payload = coseCompliantSerializer.encodeToByteArray(
                        ByteStringWrapper(
                            DeviceAuthentication(
                                type = DeviceAuthentication.TYPE,
                                sessionTranscript = calcIsoSessionTranscript(),
                                docType = input.docType,
                                namespaces = input.deviceNameSpaceBytes,
                            )
                        )
                    ).wrapInCborTag(24),
                    serializer = ByteArraySerializer(),
                ).getOrThrow()
            }
        ),
        credentialPresentationRequest = CredentialPresentationRequestBuilder(requestedCredential).toDCQLRequest()!!,
    ).getOrThrow()
        .shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
        .verifiablePresentations.values.shouldBeSingleton().first().shouldBeSingleton().first()
        .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
        .deviceResponse

    val sealed = hpke.SealBase(
        pkR = isoMdocRequest.encryptionInfo.encryptionParameters.recipientPublicKey
            .toCryptoPublicKey().getOrThrow() as CryptoPublicKey.EC,
        info = coseCompliantSerializer.encodeToByteArray(sessionTranscript),
        aad = byteArrayOf(),
        pt = coseCompliantSerializer.encodeToByteArray(deviceResponse),
    )
    return DCAPIResponse(
        EncryptedResponse(TYPE_DCAPI, EncryptedResponseData(sealed.encapsulatedSecret, sealed.ciphertext))
    )
}

/** Cipher suite to encrypt responses acc. to ISO/IEC 18013-7 Annex C */
private val hpke = HPKE(HPKE.KEM.DHKEM_P256_HKDF_SHA256, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_128_GCM)
