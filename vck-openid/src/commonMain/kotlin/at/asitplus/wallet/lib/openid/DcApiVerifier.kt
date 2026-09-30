package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.DCAPIHandover.Companion.TYPE_DCAPI
import at.asitplus.dcapi.DCAPIInfo
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.dcapi.OpenId4VpResponse
import at.asitplus.dcapi.SessionTranscriptContentHashable
import at.asitplus.dcapi.request.IsoMdocRequest
import at.asitplus.dcapi.request.verifier.CredentialRequestOptions
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.*
import at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4Vp.SignedDataElement
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.EncryptionInfo
import at.asitplus.iso.EncryptionParameters
import at.asitplus.iso.ReaderAuthentication
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.serializeOrigin
import at.asitplus.iso.sha256
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.dcql.toIso180137AnnexCDeviceRequest
import at.asitplus.rfc6749OAuth2AuthorizationFramework.ResponseType
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.MdocDeviceSignatureVerifier
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier.ChallengeSession
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.IsoDeviceRetrieval
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.ktor.utils.io.core.*
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads

/**
 * Implements a verifier for the [Digital Credentials API](https://www.w3.org/TR/digital-credentials/),
 * similar to [OpenId4VpVerifier] for OpenID4VP.
 *
 * This class creates the request for the Digital Credentials API in [createAuthnRequest]
 * (see [at.asitplus.dcapi.request.verifier.CredentialRequestOptions]), which the relying party's frontend
 * needs to pass to the browser (`navigator.credentials.get()`). The browser forwards it to the holder
 * (see [OpenId4VpHolder]), which will create the Authentication Response,
 * which will be verified here in [validateAuthnResponse].
 */
class DcApiVerifier @JvmOverloads constructor(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Key material to sign the authentication request with [signAuthnRequest]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Verifies the holder's response against our identifier from [clientIdScheme]. */
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    /**
     * Long-lived key advertised in [metadata] so that holders can encrypt responses, but **only** for client
     * identifier schemes that do not convey client metadata in the request, i.e. where this key is distributed
     * out-of-band. This is not conformant to OpenID4VC HAIP, so leave it `null` to have every request carry its own
     * ephemeral encryption key, see [ephemeralEncryptionKeyService].
     */
    private val decryptionKeyMaterial: KeyMaterial? = null,
    /** Creates one ephemeral encryption key per authentication request (Annex C and OpenID4VP) */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
    @Deprecated("Will be derived from [ephemeralEncryptionKeyService] and [decryptionKeyMaterial]")
    private val decryptJwe: DecryptJweFun =
        DecryptJweWithEphemeralKey(ephemeralEncryptionKeyService, decryptionKeyMaterial),
    /** Signs authentication requests for signed DC API requests. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters> =
        SignJwt(keyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
    /** Validates signed responses from holders. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Advertised in [metadata]. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Used to verify session transcripts from mDoc responses. */
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    /** Creates and validates OpenID4VP request nonces. */
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Used to store issued requests to verify the response to it */
    private val stateToIsoMdocRequestStore: MapStore<String, IsoMdocRequest> = DefaultMapStore(),
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
    /**
     * Signs `readerAuth` of ISO 18013-7 Annex C document requests, when [keyMaterial] has a certificate,
     * transporting the certificate chain of [clientIdScheme].
     */
    private val signReaderAuth: SignCoseDetachedFun<ByteArray> = SignCoseDetached(
        keyMaterial = keyMaterial,
        unprotectedHeaderModifier = CoseHeaderClientIdScheme(clientIdScheme),
    ),
) {
    private val mdocDeviceSignatureVerifier = MdocDeviceSignatureVerifier(verifyCoseSignature = verifyCoseSignature)

    /** Cipher suite to decrypt responses acc. to ISO/IEC 18013-7 Annex C */
    private val hpke = HPKE(HPKE.KEM.DHKEM_P256_HKDF_SHA256, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_128_GCM)

    private val nonceAwareVerifier = NonceChallengeVerifier(
        verifierId = clientIdScheme.clientId,
        verifier = verifier,
        nonceService = nonceService,
    )
    private val requestFactory = OpenId4VpRequestFactory(
        clientIdScheme = clientIdScheme,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        decryptionKeyMaterial = decryptionKeyMaterial,
        signAuthnRequest = signAuthnRequest,
        nonceService = nonceService,
        supportedAlgorithms = supportedAlgorithms,
        stateToAuthnRequestStore = stateToAuthnRequestStore,
        supportedJweEncryptionAlgorithms = supportedJweEncryptionAlgorithms,
    )
    private val vpTokenValidator = VpTokenValidator(
        mdocDeviceSignatureVerifier = mdocDeviceSignatureVerifier,
        createSessionTranscript = DcApiSessionTranscriptCalculator(),
        decryptionKeyMaterial = decryptionKeyMaterial,
    )
    private val responseParser = ResponseParser(
        decryptJwe = DecryptJweWithEphemeralKey(ephemeralEncryptionKeyService, decryptionKeyMaterial),
        verifyJwsObject = verifyJwsObject
    )

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption, i.e. without any key to encrypt
     * responses to (see [metadataWithEncryption])
     */
    val metadata get() = requestFactory.metadata

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.encryptedResponseEncValues], advertising [decryptionKeyMaterial].
     *
     * Only useful to publish out-of-band: requests carry a key specific to that request instead.
     */
    val metadataWithEncryption get() = requestFactory.metadataWithEncryption

    /**
     * Creates a new authentication request for the W3C Digital Credentials API, i.e. the object that the
     * relying party's frontend needs to pass to the browser in `navigator.credentials.get()`.
     *
     * [requestOptions] must use [OpenIdConstants.ResponseMode.DcApi] or [OpenIdConstants.ResponseMode.DcApiJwt].
     *
     * Pass more than one [creationOptions] to offer the same request over several exchange protocols in one
     * browser call, e.g. [DcApiCreationOptions.OpenId4VpSigned] and [DcApiCreationOptions.Iso180137AnnexC].
     * Do not combine [DcApiCreationOptions.OpenId4VpSigned] and [DcApiCreationOptions.OpenId4VpUnsigned],
     * as the stored requests to validate the response would overwrite each other.
     */
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        vararg creationOptions: DcApiCreationOptions,
    ): KmmResult<CredentialRequestOptions> = catching {
        require(requestOptions.isAnyDcApi) {
            "responseMode must be ${OpenIdConstants.ResponseMode.DcApi} or ${OpenIdConstants.ResponseMode.DcApiJwt}"
        }
        require(creationOptions.isNotEmpty()) {
            "at least one creation option is required"
        }
        CredentialRequestOptions.create(
            creationOptions.map { it.toGetRequest(requestOptions) }
        )
    }

    private suspend fun DcApiCreationOptions.toGetRequest(
        requestOptions: OpenId4VpRequestOptions,
    ): DigitalCredentialGetRequest = when (this) {
        is DcApiCreationOptions.OpenId4VpUnsigned -> OpenId4VpUnsigned(
            // client_id MUST be omitted in unsigned requests, per OpenID4VP 1.0 Appendix A.3.1
            requestFactory.createPlainAuthnRequest(requestOptions.copy(populateClientId = false))
        )

        is DcApiCreationOptions.OpenId4VpSigned -> OpenId4VpSigned(
            SignedDataElement(
                requestFactory.createSignedRequestObject(
                    requestOptions,
                    RequestObjectSigning.DcApi,
                ).getOrThrow().jws
            )
        )

        DcApiCreationOptions.Iso180137AnnexC -> {
            // the recipient key is ephemeral for this request, and recovered in [validateIsoResponse]
            val encryptionInfo = EncryptionInfo(
                type = TYPE_DCAPI,
                encryptionParameters = EncryptionParameters(
                    nonceService.provideNonce().toByteArray(),
                    ephemeralEncryptionKeyService.createKey(requestOptions.state)
                        .publicKey.toCoseKey().getOrThrow()
                )
            )
            val deviceRequest = when (requestOptions.presentationRequest) {
                is DCQLRequest -> requestOptions.presentationRequest.dcqlQuery.toIso180137AnnexCDeviceRequest()
                is IsoDeviceRetrieval -> requestOptions.presentationRequest.deviceRequest
                else -> throw IllegalArgumentException(
                    "ISO 18013-7 Annex C requires a Device Request or DCQL presentation"
                )
            }.withRegistrationCertificate(requestOptions.euWrprc)
                .withReaderAuthentication(encryptionInfo, requestOptions.expectedOrigins)
            IsoMdoc(
                IsoMdocRequest(deviceRequest = deviceRequest, encryptionInfo = encryptionInfo)
                    .also { stateToIsoMdocRequestStore.put(requestOptions.state, it) }
            )
        }
    }

    /** Sets [euWrprc] in the request info of every document request, as it is covered by `readerAuth`. */
    private fun DeviceRequest.withRegistrationCertificate(euWrprc: ByteArray?): DeviceRequest =
        if (euWrprc == null) this else copy(
            docRequests = docRequests.map { docRequest ->
                val itemsRequest = docRequest.itemsRequest.value
                val requestInfo = (itemsRequest.requestInfo ?: DocRequestInfo()).copy(euWrprc = euWrprc)
                docRequest.copy(itemsRequest = ByteStringWrapper(itemsRequest.copy(requestInfo = requestInfo)))
            }.toTypedArray()
        )

    /**
     * Signs `readerAuth` of every document request (ISO/IEC 18013-5, 12.5), bound to the DC API session transcript,
     * which the wallet calculates from [encryptionInfo] and the calling origin, i.e. the single entry of
     * [expectedOrigins]. Without a certificate in [keyMaterial] there is nothing to authenticate the reader with.
     */
    private suspend fun DeviceRequest.withReaderAuthentication(
        encryptionInfo: EncryptionInfo,
        expectedOrigins: List<String>?,
    ): DeviceRequest {
        if (keyMaterial.getCertificate() == null) return this
        val origin = expectedOrigins?.singleOrNull()
            ?: return this.also { Napier.w("Not signing readerAuth, requires one expected origin: $expectedOrigins") }
        val serializedOrigin = origin.serializeOrigin()
            ?: throw IllegalArgumentException("Expected origin invalid: $origin")
        val sessionTranscript = createDcApiSessionTranscriptAnnexC(DCAPIInfo(encryptionInfo, serializedOrigin))
        return copy(
            docRequests = docRequests.map { docRequest ->
                docRequest.copy(
                    readerAuth = signReaderAuth(
                        protectedHeader = null,
                        unprotectedHeader = CoseHeader(),
                        payload = ReaderAuthentication.detachedPayload(docRequest, sessionTranscript),
                        serializer = ByteArraySerializer(),
                    ).getOrThrow()
                )
            }.toTypedArray()
        )
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a signed or unsigned DC API response.
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store.
     */
    suspend fun validateAuthnResponse(
        input: String,
        externalId: String,
        expectedOrigin: String? = null,
    ): KmmResult<DcApiResponseResult> = catching {
        validateAuthnResponse(
            input = joseCompliantSerializer.decodeFromString<DigitalCredentialInterface>(input),
            externalId = externalId,
            expectedOrigin = expectedOrigin,
        ).getOrThrow()
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a signed or unsigned DC API response.
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store.
     */
    suspend fun validateAuthnResponse(
        input: DigitalCredentialInterface,
        externalId: String,
        expectedOrigin: String? = null,
    ): KmmResult<DcApiResponseResult> = catching {
        when (input) {
            is IsoMdocResponse -> validateIsoResponse(
                receivedData = input.data,
                externalId = externalId,
                expectedOrigin = requireNotNull(expectedOrigin) {
                    "expectedOrigin is required for ISO mdoc responses"
                },
            ).getOrThrow()

            else -> validateAuthnResponse(
                input = responseParser.parseAuthnResponse(input as OpenId4VpResponse),
                externalId = externalId,
                expectedOrigin = requireNotNull(expectedOrigin) {
                    "expectedOrigin is required for OpenID4VP responses"
                },
            ).getOrThrow()
        }
    }

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store,
     * in case a `state` parameter was not available in the request (e.g., when using DCAPI).
     */
    internal suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
        externalId: String,
        expectedOrigin: String,
    ): KmmResult<AuthnResponseResult> = catching {
        Napier.d("validateAuthnResponse: $input")
        val authnRequest = requestFactory.loadAuthnRequest(input, externalId)

        // the request has been consumed above, and an authentication response is not retryable,
        // so end the challenge's lifecycle here, no matter how validating the response turns out
        val session = nonceAwareVerifier.consumeChallenge(
            authnRequest.nonce ?: throw IllegalArgumentException("nonce not present in $authnRequest")
        )

        val responseType = authnRequest.responseType?.let { ResponseType(it) }
        require(responseType != null) {
            "No response type was specified in the original authentication request."
        }
        require(OpenIdConstants.VP_TOKEN in responseType) {
            "Unsupported response type: $responseType"
        }

        AuthnResponseResult(
            idTokenValidationResult = null,
            vpTokenValidationResult = validateVpToken(authnRequest, input, expectedOrigin, session),
            request = authnRequest,
        )
    }

    internal suspend fun validateIsoResponse(
        receivedData: DCAPIResponse,
        externalId: String,
        expectedOrigin: String
    ): KmmResult<Iso180137AnnexCWrapper> = catching {
        val isoMdocRequest = stateToIsoMdocRequestStore.remove(externalId)
            ?: throw IllegalStateException("Can't load request for response to $externalId")
        val decryptionKey = ephemeralEncryptionKeyService.consumeKey(externalId)?.getUnderLyingSigner() as? Signer.ECDSA
            ?: throw IllegalStateException("Can't load ephemeral decryption key for response to $externalId")
        val serializedOrigin = expectedOrigin.serializeOrigin()
            ?: throw IllegalStateException("Expected origin invalid")
        val encryptedResponseData = receivedData.response.encryptedResponseData
        val sessionTranscript = createDcApiSessionTranscriptAnnexC(
            DCAPIInfo(
                encryptionInfo = isoMdocRequest.encryptionInfo,
                serializedOrigin = serializedOrigin,
            )
        )
        val encodedSessionTranscript = coseCompliantSerializer.encodeToByteArray(sessionTranscript)
        val encodedDeviceResponse = hpke.OpenBase(
            enc = encryptedResponseData.enc,
            skR = decryptionKey,
            info = encodedSessionTranscript,
            aad = byteArrayOf(),
            ct = encryptedResponseData.cipherText,
        )
        val deviceResponse = coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(encodedDeviceResponse)

        val documents = verifier.verifyPresentationIsoMdoc(
            input = deviceResponse,
            verifyDocument = mdocDeviceSignatureVerifier.verifyDocument(
                sessionTranscript = sessionTranscript
            )
        ).getOrThrow().documents

        // an authentic document of a type we never asked for must not be mistaken for the requested one
        val requestedDocTypes = isoMdocRequest.deviceRequest.docRequests
            .map { it.itemsRequest.value.docType }.toSet()
        documents.forEach { document ->
            require(document.document.docType in requestedDocTypes) {
                "Response contains docType '${document.document.docType}', but requested were $requestedDocTypes"
            }
        }

        Iso180137AnnexCWrapper(documents)
    }

    /**
     * Validates the `vp_token` of the response with the shared [VpTokenValidator],
     * enforcing this verifier's transport: the Digital Credentials API.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        expectedOrigin: String,
        session: ChallengeSession,
    ): KmmResult<VpTokenValidationResult> = catching {
        val originalResponseParameters = responseParameters.originalResponseParameters
        require(originalResponseParameters is ResponseParametersFrom.DcApi) {
            "Unsupported response parameters: $originalResponseParameters"
        }
        if (originalResponseParameters.clientIdRequired) {
            // is signed request
            require(authnRequest.verifyExpectedOrigin(expectedOrigin)) {
                "expected origin '$expectedOrigin' does not match expected_origins"
            }
        }
        vpTokenValidator.validateVpToken(
            authnRequest = authnRequest,
            responseParameters = responseParameters,
            origin = expectedOrigin,
            session = session,
        ).getOrThrow()
    }

    fun createDcApiSessionTranscriptAnnexC(
        toBeHashed: SessionTranscriptContentHashable,
    ): SessionTranscript = SessionTranscript.forDcApi(
        DCAPIHandover(
            type = TYPE_DCAPI,
            hash = coseCompliantSerializer.encodeToByteArray(
                toBeHashed as? DCAPIInfo ?: throw IllegalStateException("Expected DCAPIInfo")
            ).sha256(),
        )
    )
}
