package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.OpenId4VpHandover
import at.asitplus.iso.OpenId4VpHandoverInfo
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IdToken
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.JarRequestParameters.RequestUriMethod
import at.asitplus.openid.JarRequestParameters.RequestUriMethod.GET
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.SupportedAlgorithmsContainerIso
import at.asitplus.openid.SupportedAlgorithmsContainerJwt
import at.asitplus.openid.SupportedAlgorithmsContainerSdJwt
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.DecryptJwe
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.sessionTranscriptThumbprint
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/**
 * Combines Verifiable Presentations with OAuth 2.0.
 * Implements [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (1.0, 2025-07-09)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (D13, 2023-11-28).
 *
 * This class creates the Authentication Request (see [AuthenticationRequestParameters]),
 * clients need to send it to the holder (see [OpenId4VpHolder]) which will create the Authentication Response,
 * which will be verified here in [validateAuthnResponse].
 */
class OpenId4VpVerifier(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Key material to sign the authentication request with [signAuthnRequest]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Verifies the holder's response against our identifier from [clientIdScheme]. */
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    /** Advertised in [metadata] so that holders can encrypt responses. */
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Decrypts encrypted responses from holders. */
    private val decryptJwe: DecryptJweFun = DecryptJwe(decryptionKeyMaterial),
    /** Signs authentication requests in [createAuthnRequestAsSignedRequestObject]. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters> =
        SignJwt(keyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
    /** Validates signed responses from holders. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Advertised in [metadata]. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Used to verify session transcripts from mDoc responses. */
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    /** Leeway for time validity checks. */
    timeLeewaySeconds: Long = 300L,
    /** Clock for time validity checks. */
    private val clock: Clock = Clock.System,
    /** Creates challenges in authentication requests. */
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    @Deprecated("Use supportedJweEncryptionAlgorithms instead")
    private val supportedJweAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES,
    @Deprecated("Use supportedJweEncryptionAlgorithms instead")
    private val supportedJweEncryptionAlgorithm: JweEncryption = JweEncryption.A256GCM,
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
) {

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val responseParser = ResponseParser(decryptJwe, verifyJwsObject)
    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val containerJwt = FormatContainerJwt(algorithmStrings = supportedJwsAlgorithms)
    private val containerSdJwt = FormatContainerSdJwt(
        sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
        kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet()
    )

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption (see [metadataWithEncryption])
     */
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.redirectUri),
            jsonWebKeySet = JsonWebKeySet(
                listOf(
                    decryptionKeyMaterial.publicKey.toJsonWebKey(decryptionKeyMaterial.identifier).withAlgorithm()
                )
            ),
            vpFormatsSupported = VpFormatsSupported(
                vcJwt = SupportedAlgorithmsContainerJwt(
                    algorithmStrings = supportedJwsAlgorithms.toSet()
                ),
                dcSdJwt = SupportedAlgorithmsContainerSdJwt(
                    sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                    kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                ),
                msoMdoc = SupportedAlgorithmsContainerIso(
                    issuerAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                    deviceAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                ),
            )
        )
    }

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.encryptedResponseEncValues].
     */
    @Suppress("DEPRECATION")
    val metadataWithEncryption by lazy {
        metadata.copy(
            encryptedResponseEncValuesSupportedString = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
            jsonWebKeySet = metadata.jsonWebKeySet?.let {
                JsonWebKeySet(it.keys.map { it.copy(publicKeyUse = "enc") })
            }
        )
    }

    /**
     * Options for creating authorization requests (query, by value, or by reference).
     * Use to control how the verifier delivers the request to the wallet.
     */
    sealed class CreationOptions {
        /**
         * Creates authentication request with parameters encoded as URL query parameters to [walletUrl].
         */
        data class Query(val walletUrl: String) : CreationOptions()

        /**
         * Appends [requestUrl] to [walletUrl], callers need to call [CreatedRequest.loadRequestObject] with the
         * Wallet's request to actually create the authn request object.
         **/
        data class RequestByReference(
            val walletUrl: String,
            val requestUrl: String,
            val requestUrlMethod: RequestUriMethod = GET,
        ) : CreationOptions()

        /** Appends authentication request as signed object to [walletUrl] */
        data class SignedRequestByValue(val walletUrl: String) : CreationOptions()

        /**
         * Appends [requestUrl] to [walletUrl], callers need to call [CreatedRequest.loadRequestObject] with the
         * Wallet's request to actually create the authn request object (which will be signed).
         */
        data class SignedRequestByReference(
            val walletUrl: String,
            val requestUrl: String,
            val requestUrlMethod: RequestUriMethod = GET,
        ) : CreationOptions()
    }

    data class CreatedRequest(
        /** URL to invoke the wallet/holder */
        val url: String,
        /**
         *  Optional content that needs to be served under the previously passed in `requestUrl`
         *  with content type `application/oauth-authz-req+jwt`
         *  Pass in the [RequestObjectParameters] that the Wallet may have sent when requesting the request object.
         */
        val loadRequestObject: (suspend (RequestObjectParameters?) -> KmmResult<String>)? = null,
    )

    suspend fun createAuthnRequest(
        requestOptions: RequestOptions,
        creationOptions: CreationOptions,
    ): KmmResult<CreatedRequest> = catching {
        when (creationOptions) {
            is CreationOptions.Query -> {
                require(clientIdScheme !is ClientIdScheme.CertificateSanDns) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    createAuthnRequest(requestOptions).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.RequestByReference -> {
                require(clientIdScheme !is ClientIdScheme.CertificateSanDns) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest {
                    catching {
                        vckJsonSerializer.encodeToString(createAuthnRequest(requestOptions, it))
                    }
                }
            }

            is CreationOptions.SignedRequestByValue -> {
                require(clientIdScheme !is ClientIdScheme.RedirectUri) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        request = createAuthnRequestAsSignedRequestObject(requestOptions).getOrThrow().serialize(),
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.SignedRequestByReference -> {
                require(clientIdScheme !is ClientIdScheme.RedirectUri) // per OpenID4VP d23 5.10.4
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString()
                    .toCreatedRequest {
                        catching {
                            createAuthnRequestAsSignedRequestObject(requestOptions, it).getOrThrow().serialize()
                        }
                    }
            }
        }
    }

    private fun String.toCreatedRequest() = CreatedRequest(this)
    private fun String.toCreatedRequest(
        loadRequestObject: suspend (RequestObjectParameters?) -> KmmResult<String>,
    ) = CreatedRequest(this, loadRequestObject)


    /**
     * Creates an JWS Authorization Request (JAR, RFC9101), wrapping the usual [AuthenticationRequestParameters].
     *
     * To use this for an Authentication Request with `request_uri`, use the following code,
     * `jar` being the result of this function:
     * ```
     * val urlToSendToWallet = io.ktor.http.URLBuilder(walletUrl).apply {
     *    parameters.append("client_id", clientId)
     *    parameters.append("request_uri", requestUrl)
     * }.buildString()
     * // on an GET to requestUrl, return `jar.serialize()`
     * ```
     */
    suspend fun createAuthnRequestAsSignedRequestObject(
        requestOptions: RequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ): KmmResult<JwsSigned<AuthenticationRequestParameters>> = catching {
        val requestObject = createAuthnRequest(requestOptions, requestObjectParameters)
        val siopClientId = "https://self-issued.me/v2"
        val issuer = when (clientIdScheme) {
            is ClientIdScheme.PreRegistered -> clientIdScheme.issuerUri ?: clientIdScheme.clientId
            else -> siopClientId
        }
        signAuthnRequest(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            requestObject.copy(
                audience = siopClientId,
                issuer = issuer,
            ),
            AuthenticationRequestParameters.serializer(),
        ).getOrThrow()
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded in the URL of the wallet somehow,
     * see [createAuthnRequest]
     */
    suspend fun createAuthnRequest(
        requestOptions: RequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ) = prepareAuthnRequest(
        requestOptions = requestOptions,
        requestObjectParameters = requestObjectParameters,
    ).also {
        submitAuthnRequest(it, requestOptions.state)
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded in the URL of the wallet somehow,
     * see [createAuthnRequest]
     */
    suspend fun prepareAuthnRequest(
        requestOptions: RequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ) = requestOptions.toAuthnRequest(requestObjectParameters)

    private suspend fun RequestOptions.toAuthnRequest(
        requestObjectParameters: RequestObjectParameters?,
    ): AuthenticationRequestParameters = AuthenticationRequestParameters(
        responseType = responseType,
        clientId = clientIdScheme.clientId,
        redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
        responseUrl = responseUrl,
        // Using scope as an alias for a well-defined Presentation Exchange or DCQL is not supported
        scope = if (isSiop) buildScope() else null,
        nonce = nonceService.provideNonce(),
        walletNonce = requestObjectParameters?.walletNonce,
        clientMetadata = clientMetadata(),
        idTokenType = if (isSiop) IdTokenType.SUBJECT_SIGNED.text else null,
        responseMode = responseMode,
        state = if (!isDcApi) state else null,
        dcqlQuery = if (isDcql) toDCQLQuery() else null,
        presentationDefinition = if (isPresentationExchange)
            toPresentationDefinition(containerJwt, containerSdJwt) else null,
        transactionData = transactionData?.map { it.toBase64UrlJsonString() }
    )

    /**
     * Remembers [authenticationRequestParameters] to link responses to requests in [validateAuthnResponse].
     *
     * Parameter [externalId] may be used in cases the [authenticationRequestParameters] do not have a `state`
     * parameter, e.g., when using DCAPI. Otherwise the value of [AuthenticationRequestParameters.state] will be used.
     */
    suspend fun submitAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
        externalId: String? = null,
    ) = stateToAuthnRequestStore.put(
        key = externalId
            ?: authenticationRequestParameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state has been provided"),
        value = authenticationRequestParameters,
    )

    @Suppress("DEPRECATION")
    private fun RequestOptions.clientMetadata(): RelyingPartyMetadata? = when (clientIdScheme) {
        is ClientIdScheme.RedirectUri,
        is ClientIdScheme.VerifierAttestation,
        is ClientIdScheme.CertificateSanDns,
        is ClientIdScheme.CertificateHash,
            ->
            if (encryption || responseMode.requiresEncryption) metadataWithEncryption else metadata

        else -> null
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponse(
        input: String,
    ): AuthnResponseResult = validateAuthnResponse(
        input = input,
        externalId = null
    )

    /**
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store,
     * in case a `state` parameter was not available in the request (e.g., when using DCAPI).
     */
    suspend fun validateAuthnResponse(
        input: String,
        externalId: String? = null,
    ): AuthnResponseResult = catchingUnwrapped {
        responseParser.parseAuthnResponse(input)
    }.getOrElse {
        return AuthnResponseResult.Error("Can't parse input: $input", cause = it)
    }.let {
        validateAuthnResponse(it, externalId)
    }

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     */
    suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
    ) = validateAuthnResponse(
        input = input,
        externalId = null,
    )

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     *
     * The [externalId] will be used to load the corresponding [AuthenticationRequestParameters] from the store,
     * in case a `state` parameter was not available in the request (e.g., when using DCAPI).
     */
    suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
        externalId: String? = null,
    ): AuthnResponseResult {
        Napier.d("validateAuthnResponse: $input")
        val authnRequest = catching {
            loadAuthnRequest(input, externalId)
        }.getOrElse {
            return AuthnResponseResult.ValidationError("input", cause = it)
        }
        // TODO: support concurrent presentation of ID token and VP token?
        return if (authnRequest.responseType?.contains(OpenIdConstants.VP_TOKEN) == true) {
            catching {
                validateVpToken(authnRequest, input)
            }.getOrElse {
                AuthnResponseResult.ValidationError("vpToken", input.parameters.state, it)
            }
        } else if (authnRequest.responseType?.contains(OpenIdConstants.ID_TOKEN) == true) {
            catching {
                extractValidatedIdToken(input)
            }.getOrElse {
                AuthnResponseResult.ValidationError("idToken", input.parameters.state, it)
            }
        } else {
            AuthnResponseResult.Error(
                reason = "Neither id_token nor vp_token",
                state = authnRequest.state,
                cause = IllegalArgumentException(authnRequest.responseType)
            )
        }
    }

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun loadAuthnRequest(
        input: ResponseParametersFrom,
        externalId: String?,
    ): AuthenticationRequestParameters {
        val storedId = externalId
            ?: input.parameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state given")
        val authnRequest = stateToAuthnRequestStore.get(storedId)
            ?: throw IllegalArgumentException("No authn request found for $storedId")
        if (authnRequest.responseMode?.requiresEncryption == true)
            require(input.hasBeenEncrypted) {
                "response_mode requires encryption, but no encrypted response was given"
            }
        return authnRequest
    }

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun extractValidatedIdToken(
        input: ResponseParametersFrom,
    ): AuthnResponseResult {
        val idTokenJws = input.parameters.idToken
            ?: throw IllegalArgumentException("idToken")
        val jwsSigned = JwsSigned.deserialize(IdToken.serializer(), idTokenJws, vckJsonSerializer)
            .getOrElse { throw IllegalArgumentException("idToken", it) }
        verifyJwsObject(jwsSigned).getOrElse {
            throw IllegalArgumentException("idToken.", it)
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        }
        val idToken = jwsSigned.payload
        if (idToken.issuer != idToken.subject)
            throw IllegalArgumentException("idToken.iss")
                .also { Napier.d("Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}") }
        if (idToken.audience != clientIdScheme.clientId)
            throw IllegalArgumentException("idToken.aud")
                .also { Napier.d("audience not valid: ${idToken.audience}") }
        if (idToken.expiration < (clock.now() - timeLeeway))
            throw IllegalArgumentException("idToken.exp")
                .also { Napier.d("expirationDate before now: ${idToken.expiration}") }
        if (idToken.issuedAt > (clock.now() + timeLeeway))
            throw IllegalArgumentException("idToken.iat")
                .also { Napier.d("issuedAt after now: ${idToken.issuedAt}") }
        if (!nonceService.verifyAndRemoveNonce(idToken.nonce)) {
            throw IllegalArgumentException("idToken.nonce")
                .also { Napier.d("nonce not valid: ${idToken.nonce}, not known to us") }
        }
        if (idToken.subjectJwk == null)
            throw IllegalArgumentException("idToken.sub_jwk")
                .also { Napier.d("sub_jwk is null") }
        if (idToken.subject != idToken.subjectJwk!!.jwkThumbprint)
            throw IllegalArgumentException("idToken.sub")
                .also { Napier.d("subject does not equal thumbprint of sub_jwk: ${idToken.subject}") }
        return AuthnResponseResult.IdToken(idToken, input.parameters.state)
    }

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
    ): AuthnResponseResult {
        val expectedNonce = authnRequest.nonce
            ?: throw IllegalArgumentException("nonce")
        val vpToken = responseParameters.parameters.vpToken
            ?: throw IllegalArgumentException("vp_token")

        return authnRequest.presentationDefinition?.let { presentationDefinition ->
            val presentationSubmission = responseParameters.parameters.presentationSubmission?.descriptorMap
                ?: throw IllegalArgumentException("Presentation Exchange need to present a presentation submission.")

            presentationSubmission.map { descriptor ->
                verifyPresentationResult(
                    claimFormat = descriptor.format,
                    relatedPresentation = descriptor.relatedPresentation(vpToken),
                    expectedNonce = expectedNonce,
                    input = responseParameters,
                    clientId = authnRequest.clientId,
                    responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted,
                    transactionData = authnRequest.transactionData,
                ).mapToAuthnResponseResult(responseParameters.parameters.state)
            }.firstOrList()
        } ?: authnRequest.dcqlQuery?.let { query ->
            val presentation = vpToken.jsonObject.mapKeys {
                DCQLCredentialQueryIdentifier(it.key)
            }.mapValues { (credentialQueryId, relatedPresentation) ->
                val credentialQuery = query.credentialQuery(credentialQueryId)
                    ?: throw IllegalArgumentException("Unknown credential query identifier.")

                catchingUnwrapped {
                    verifyPresentationResult(
                        claimFormat = credentialQuery.format.toClaimFormat(),
                        relatedPresentation = relatedPresentation,
                        expectedNonce = expectedNonce,
                        input = responseParameters,
                        clientId = authnRequest.clientId,
                        responseUrl = authnRequest.responseUrl ?: authnRequest.redirectUrlExtracted,
                        transactionData = authnRequest.transactionData,
                    ).mapToAuthnResponseResult(responseParameters.parameters.state)
                }.getOrElse {
                    return AuthnResponseResult.ValidationError(
                        "Invalid presentation",
                        responseParameters.parameters.state,
                        it
                    )
                }
            }
            AuthnResponseResult.VerifiableDCQLPresentationValidationResults(presentation)
        } ?: throw IllegalArgumentException("Unsupported presentation mechanism")
    }

    private fun DCQLQuery.credentialQuery(id: DCQLCredentialQueryIdentifier) =
        credentials.associateBy { it.id }[id]

    private fun PresentationSubmissionDescriptor.relatedPresentation(vpToken: JsonElement) =
        JsonPath(cumulativeJsonPath).query(vpToken).first().value

    private fun CredentialFormatEnum.toClaimFormat(): ClaimFormat = when (this) {
        CredentialFormatEnum.JWT_VC -> ClaimFormat.JWT_VP
        CredentialFormatEnum.DC_SD_JWT -> ClaimFormat.SD_JWT
        CredentialFormatEnum.MSO_MDOC -> ClaimFormat.MSO_MDOC
        CredentialFormatEnum.NONE,
        CredentialFormatEnum.JWT_VC_JSON_LD,
        CredentialFormatEnum.JSON_LD,
            -> throw IllegalStateException("Unsupported credential format")
    }

    private fun List<AuthnResponseResult>.firstOrList(): AuthnResponseResult =
        if (size == 1) this[0]
        else AuthnResponseResult.VerifiablePresentationValidationResults(this)

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    private suspend fun verifyPresentationResult(
        claimFormat: ClaimFormat,
        relatedPresentation: JsonElement,
        expectedNonce: String,
        input: ResponseParametersFrom,
        clientId: String?,
        responseUrl: String?,
        transactionData: List<TransactionDataBase64Url>?,
    ) = when (claimFormat) {
        ClaimFormat.SD_JWT -> verifier.verifyPresentationSdJwt(
            input = SdJwtSigned.parseCatching(relatedPresentation.extractContent()).getOrElse {
                throw IllegalArgumentException("relatedPresentation")
            },
            challenge = expectedNonce,
            transactionData = transactionData
        )

        ClaimFormat.JWT_VP -> verifier.verifyPresentationVcJwt(
            input = JwsSigned.deserialize(
                VerifiablePresentationJws.serializer(),
                relatedPresentation.extractContent(),
                vckJsonSerializer
            ).getOrThrow(),
            challenge = expectedNonce
        )

        ClaimFormat.MSO_MDOC -> verifier.verifyPresentationIsoMdoc(
            input = relatedPresentation.extractContent().decodeToByteArray(Base64UrlStrict)
                .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) },
            verifyDocument = verifyDocument(
                clientId = clientId,
                responseUrl = responseUrl,
                nonce = expectedNonce,
                hasBeenEncrypted = input.hasBeenEncrypted
            )
        )

        else -> throw IllegalArgumentException("descriptor.format: $claimFormat")
    }

    // To be reconsidered when supporting [DCQLCredentialQueryInstance.multiple]
    private fun JsonElement.extractContent(): String = when (this) {
        is JsonArray -> first().extractContent()
        is JsonObject -> toString()
        is JsonPrimitive -> content
        JsonNull -> throw IllegalArgumentException("Can't extract string from JsonNull")
    }

    /**
     * Performs verification of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class, IllegalStateException::class)
    private fun verifyDocument(
        clientId: String?,
        responseUrl: String?,
        nonce: String,
        hasBeenEncrypted: Boolean,
    ): suspend (MobileSecurityObject, Document) -> Boolean = { mso, document ->
        val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature
            ?: throw IllegalArgumentException("deviceSignature is null")
        if (clientId == null || responseUrl == null)
            throw IllegalStateException("Missing required parameters: clientId, responseUrl")
        val expected = document.calcDeviceAuthenticationOpenId4VpFinal(
            clientId = clientId,
            responseUrl = responseUrl,
            nonce = nonce,
            hasBeenEncrypted = hasBeenEncrypted
        ).wrapAsExpectedPayload()

        verifyCoseSignature(
            coseSigned = deviceSignature,
            signer = mso.deviceKeyInfo.deviceKey,
            externalAad = byteArrayOf(),
            detachedPayload = expected
        ).onFailure {
            throw IllegalArgumentException("deviceSignature not matching ${expected.encodeToString(Base16())}", it)
        }
        true
    }

    private fun DeviceAuthentication.wrapAsExpectedPayload(): ByteArray = coseCompliantSerializer
        .encodeToByteArray(coseCompliantSerializer.encodeToByteArray(this))
        .wrapInCborTag(24)

    /**
     * Performs calculation of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to OpenID4VP 1.0
     */
    private fun Document.calcDeviceAuthenticationOpenId4VpFinal(
        clientId: String,
        responseUrl: String,
        nonce: String,
        hasBeenEncrypted: Boolean,
    ) = DeviceAuthentication(
        type = DeviceAuthentication.TYPE,
        sessionTranscript = SessionTranscript.forOpenId(
            OpenId4VpHandover(
                type = OpenId4VpHandover.TYPE_OPENID4VP,
                hash = coseCompliantSerializer.encodeToByteArray<OpenId4VpHandoverInfo>(
                    OpenId4VpHandoverInfo(
                        clientId = clientId,
                        nonce = nonce,
                        jwkThumbprint = if (hasBeenEncrypted) {
                            decryptionKeyMaterial.jsonWebKey.sessionTranscriptThumbprint()
                        } else null,
                        responseUrl = responseUrl,
                    )
                ).sha256(),
            )
        ),
        docType = docType,
        namespaces = deviceSigned.namespaces
    )

    private fun VerifyPresentationResult.mapToAuthnResponseResult(state: String?) = when (this) {
        is VerifyPresentationResult.ValidationError -> AuthnResponseResult.ValidationError("vpToken", state, cause)
        is VerifyPresentationResult.Success -> AuthnResponseResult.Success(vp, state)
        is VerifyPresentationResult.SuccessIso -> AuthnResponseResult.SuccessIso(documents, state)
        is VerifyPresentationResult.SuccessSdJwt -> AuthnResponseResult.SuccessSdJwt(
            sdJwtSigned = sdJwtSigned,
            verifiableCredentialSdJwt = verifiableCredentialSdJwt,
            reconstructed = reconstructedJsonObject,
            disclosures = disclosures,
            state = state,
            freshnessSummary = freshnessSummary,
        )
    }

    // should always be ecdh-es for encryption
    private fun JsonWebKey.withAlgorithm(): JsonWebKey = this.copy(algorithm = JweAlgorithm.ECDH_ES)
}


private val PresentationSubmissionDescriptor.cumulativeJsonPath: String
    get() {
        var cummulativeJsonPath = this.path
        var descriptorIterator = this.nestedPath
        while (descriptorIterator != null) {
            cummulativeJsonPath += descriptorIterator.path.substring(1)
            descriptorIterator = descriptorIterator.nestedPath
        }
        return cummulativeJsonPath
    }


class JwsHeaderClientIdScheme(val clientIdScheme: ClientIdScheme) : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = when (clientIdScheme) {
        is ClientIdScheme.CertificateHash -> it.copy(certificateChain = clientIdScheme.chain)
        is ClientIdScheme.CertificateSanDns -> it.copy(certificateChain = clientIdScheme.chain)
        is ClientIdScheme.VerifierAttestation -> it.copy(
            jsonWebKey = keyMaterial.jsonWebKey,
            attestationJwt = clientIdScheme.attestationJwt.serialize()
        )

        else -> it.copy(jsonWebKey = keyMaterial.jsonWebKey)
    }
}
