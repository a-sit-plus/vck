package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.OID4VPHandover
import at.asitplus.dif.ClaimFormat
import at.asitplus.dif.FormatContainerJwt
import at.asitplus.dif.FormatContainerSdJwt
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.PresentationSubmissionDescriptor
import at.asitplus.iso.ClientIdToHash
import at.asitplus.iso.DeviceAuthentication
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ResponseUriToHash
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.jsonpath.JsonPath
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.IdToken
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.JarRequestParameters.RequestUriMethod
import at.asitplus.openid.JarRequestParameters.RequestUriMethod.POST
import at.asitplus.openid.JwtVcIssuerMetadata
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
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
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
import at.asitplus.wallet.lib.oidvci.decode
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OpenID for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2024-12-02)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-11-28).
 *
 * This class creates the Authentication Request, [verifier] verifies the response.
 * See [OpenId4VpHolder] for the holder side, i.e. the Wallet.
 */
class OpenId4VpVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    private val decryptionKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val decryptJwe: DecryptJweFun = DecryptJwe(decryptionKeyMaterial),
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters> =
        SignJwt(keyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests, to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Algorithm supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweAlgorithm: JweAlgorithm = JweAlgorithm.ECDH_ES,
    /** Algorithm supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithm: JweEncryption = JweEncryption.A256GCM,
) {

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val responseParser = ResponseParser(decryptJwe, verifyJwsObject)
    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val supportedSignatureVerificationAlgorithm =
        supportedJwsAlgorithms.firstOrNull  { it == JwsAlgorithm.Signature.EC.ES256.identifier }
            ?: supportedJwsAlgorithms.first()
    private val containerJwt = FormatContainerJwt(algorithmStrings = supportedJwsAlgorithms)
    private val containerSdJwt = FormatContainerSdJwt(
        sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
        kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet()
    )

    /**
     * Serve this result JSON-serialized under `/.well-known/jar-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_JAR_ISSUER]),
     * so that SIOP Wallets can look up the keys used to sign request objects.
     */
    val jarMetadata: JwtVcIssuerMetadata by lazy {
        JwtVcIssuerMetadata(
            issuer = clientIdScheme.issuerUri ?: clientIdScheme.clientId,
            jsonWebKeySet = JsonWebKeySet(setOf(keyMaterial.jsonWebKey))
        )
    }

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption (see [metadataWithEncryption])
     */
    @Suppress("DEPRECATION")
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.redirectUri),
            jsonWebKeySet = JsonWebKeySet(listOf(decryptionKeyMaterial.publicKey.toJsonWebKey())),
            authorizationSignedResponseAlgString = supportedSignatureVerificationAlgorithm,
            vpFormats = FormatHolder(
                msoMdoc = containerJwt,
                jwtVp = containerJwt,
                jwtSd = containerSdJwt,
                sdJwt = containerSdJwt
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
     * responses, see [RelyingPartyMetadata.authorizationEncryptedResponseAlg]
     * and [RelyingPartyMetadata.authorizationEncryptedResponseEncoding].
     */
    val metadataWithEncryption by lazy {
        metadata.copy(
            authorizationSignedResponseAlgString = null,
            authorizationEncryptedResponseAlgString = supportedJweAlgorithm.identifier,
            authorizationEncryptedResponseEncodingString = supportedJweEncryptionAlgorithm.identifier,
            encryptedResponseEncryptionString = setOf(supportedJweEncryptionAlgorithm.identifier),
            jsonWebKeySet = metadata.jsonWebKeySet?.let {
                JsonWebKeySet(it.keys.map { it.copy(publicKeyUse = "enc") })
            }
        )
    }

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
            val requestUrlMethod: RequestUriMethod = POST,
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
            val requestUrlMethod: RequestUriMethod = POST,
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
        submitAuthnRequest(it)
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded in the URL of the wallet somehow,
     * see [createAuthnRequest]
     */
    suspend fun prepareAuthnRequest(
        requestOptions: RequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ) = requestOptions.toAuthnRequest(requestObjectParameters)

    @Suppress("DEPRECATION")
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
        clientMetadata = clientMetadata(this),
        clientMetadataUri = clientMetadataUrl,
        idTokenType = if (isSiop) IdTokenType.SUBJECT_SIGNED.text else null,
        responseMode = responseMode,
        state = state,
        dcqlQuery = if (isDcql) toDCQLQuery() else null,
        presentationDefinition = if (isPresentationExchange)
            toPresentationDefinition(containerJwt, containerSdJwt) else null,
        transactionData = transactionData?.map { it.toBase64UrlJsonString() }
    )

    /**
     * Remembers [authenticationRequestParameters] to link responses to requests
     */
    suspend fun submitAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
    ) = stateToAuthnRequestStore.put(
        authenticationRequestParameters.state
            ?: throw IllegalArgumentException("No state value has been provided"),
        authenticationRequestParameters,
    )

    // OpenID4VP: Metadata MUST be passed as parameter if client_id_scheme is "redirect_uri"
    @Suppress("DEPRECATION")
    private fun clientMetadata(options: RequestOptions): RelyingPartyMetadata? =
        if (options.clientMetadataUrl != null && clientIdScheme !is ClientIdScheme.RedirectUri) {
            null
        } else {
            if (options.encryption) metadataWithEncryption else metadata
        }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a map of POST parameters received.
     */
    suspend fun validateAuthnResponse(input: Map<String, String>): AuthnResponseResult =
        catchingUnwrapped {
            ResponseParametersFrom.Post(input.decode<AuthenticationResponseParameters>())
        }.getOrElse {
            return AuthnResponseResult.Error("Can't parse input: $input", null, it)
        }.let { validateAuthnResponse(it) }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponse(input: String): AuthnResponseResult =
        catchingUnwrapped {
            responseParser.parseAuthnResponse(input)
        }.getOrElse {
            return AuthnResponseResult.Error("Can't parse input: $input", null, it)
        }.let {
            validateAuthnResponse(it)
        }

    /**
     * Validates [AuthenticationResponseParameters] from the Wallet
     */
    suspend fun validateAuthnResponse(input: ResponseParametersFrom): AuthnResponseResult {
        Napier.d("validateAuthnResponse: $input")
        val params = input.parameters
        val state = params.state
            ?: return AuthnResponseResult.ValidationError("state", params.state)
        val authnRequest = stateToAuthnRequestStore.get(state)
            ?: return AuthnResponseResult.ValidationError("state", state)

        // TODO: support concurrent presentation of ID token and VP token?
        val responseType = authnRequest.responseType
        if (responseType?.contains(OpenIdConstants.VP_TOKEN) == true) {
            return validateVpToken(
                authnRequest = authnRequest,
                responseParameters = input,
                state = state
            )
        }

        if (responseType?.contains(OpenIdConstants.ID_TOKEN) == true) {
            val idToken = params.idToken?.let { idToken ->
                catching {
                    extractValidatedIdToken(idToken)
                }.getOrElse {
                    return AuthnResponseResult.ValidationError("idToken", state, it)
                }
            } ?: return AuthnResponseResult.ValidationError("idToken", state)
            return AuthnResponseResult.IdToken(idToken, state)
        }

        return AuthnResponseResult.Error("Neither id_token nor vp_token", state)
    }

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun extractValidatedIdToken(idTokenJws: String): IdToken {
        val jwsSigned = JwsSigned.Companion.deserialize<IdToken>(
            IdToken.Companion.serializer(), idTokenJws,
            vckJsonSerializer
        ).getOrElse {
            throw IllegalArgumentException("idToken", it)
        }
        if (!verifyJwsObject(jwsSigned))
            throw IllegalArgumentException("idToken")
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
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
        return idToken
    }

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    private suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        state: String,
    ): AuthnResponseResult {
        val params = responseParameters.parameters
        val expectedNonce = authnRequest.nonce
            ?: return AuthnResponseResult.ValidationError("state", state)
        val verifiablePresentation = params.vpToken
            ?: return AuthnResponseResult.ValidationError("vp_token", state)

        authnRequest.presentationDefinition?.let { presentationDefinition ->
            val presentationSubmission = params.presentationSubmission
                ?: throw IllegalArgumentException("Credential presentations using Presentation Exchange need to present a presentation submission.")

            val validationResults = presentationSubmission.descriptorMap?.map { descriptor ->
                val relatedPresentation = JsonPath(descriptor.cumulativeJsonPath)
                    .query(verifiablePresentation).first().value
                val result = catchingUnwrapped {
                    verifyPresentationResult(
                        descriptor.format,
                        relatedPresentation,
                        expectedNonce,
                        responseParameters,
                        authnRequest.clientId,
                        authnRequest.responseUrl,
                        authnRequest.transactionData
                    )
                }.getOrElse {
                    return AuthnResponseResult.ValidationError("Invalid presentation", state, it)
                }
                result.mapToAuthnResponseResult(state)
            } ?: listOf()
            return validationResults.firstOrList()
        }

        authnRequest.dcqlQuery?.let { query ->
            val credentialQueryMap = query.credentials.associateBy {
                it.id
            }

            val presentation = verifiablePresentation.jsonObject.mapKeys {
                DCQLCredentialQueryIdentifier(it.key)
            }.mapValues { (credentialQueryId, relatedPresentation) ->
                val credentialQuery = credentialQueryMap[credentialQueryId]
                    ?: throw IllegalArgumentException("Unknown credential query identifier.")

                verifyPresentationResult(
                    credentialQuery.format.toClaimFormat(),
                    relatedPresentation,
                    expectedNonce,
                    responseParameters,
                    authnRequest.clientId,
                    authnRequest.responseUrl,
                    authnRequest.transactionData
                ).mapToAuthnResponseResult(state)
            }
            return AuthnResponseResult.VerifiableDCQLPresentationValidationResults(presentation)
        }

        throw IllegalArgumentException("Unsupported presentation mechanism")
    }

    private fun CredentialFormatEnum.toClaimFormat(): ClaimFormat = when (this) {
        CredentialFormatEnum.JWT_VC,
            -> ClaimFormat.JWT_VP

        @Suppress("DEPRECATION")
        CredentialFormatEnum.VC_SD_JWT,
        CredentialFormatEnum.DC_SD_JWT,
            -> ClaimFormat.SD_JWT

        CredentialFormatEnum.MSO_MDOC,
            -> ClaimFormat.MSO_MDOC

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
    @Suppress("DEPRECATION")
    private suspend fun verifyPresentationResult(
        claimFormat: ClaimFormat,
        relatedPresentation: JsonElement,
        expectedNonce: String,
        input: ResponseParametersFrom,
        clientId: String?,
        responseUrl: String?,
        transactionData: List<TransactionDataBase64Url>?,
    ) = when (claimFormat) {
        ClaimFormat.JWT_SD, ClaimFormat.SD_JWT -> verifier.verifyPresentationSdJwt(
            input = SdJwtSigned.parseCatching(relatedPresentation.jsonPrimitive.content).getOrElse {
                throw IllegalArgumentException("relatedPresentation")
            },
            challenge = expectedNonce,
            transactionData = transactionData
        )

        ClaimFormat.JWT_VP -> verifier.verifyPresentationVcJwt(
            input = JwsSigned.Companion.deserialize<VerifiablePresentationJws>(
                VerifiablePresentationJws.Companion.serializer(),
                relatedPresentation.jsonPrimitive.content,
                vckJsonSerializer
            ).getOrThrow(),
            challenge = expectedNonce
        )

        ClaimFormat.MSO_MDOC -> {
            // if the response is not encrypted, the wallet could not transfer the mdocGeneratedNonce,
            // so we'll use the empty string
            val apuDirect = (input as? ResponseParametersFrom.JweDecrypted)
                ?.jweDecrypted?.header?.agreementPartyUInfo
            val apuNested = ((input as? ResponseParametersFrom.JwsSigned)?.parent as? ResponseParametersFrom.JweForJws)
                ?.jweDecrypted?.header?.agreementPartyUInfo
            val deviceResponse = relatedPresentation.jsonPrimitive.content.decodeToByteArray(Base64UrlStrict)
                .let { coseCompliantSerializer.decodeFromByteArray<DeviceResponse>(it) }

            val mdocGeneratedNonce = apuDirect?.decodeToString()
                ?: apuNested?.decodeToString()
                ?: ""
            verifier.verifyPresentationIsoMdoc(
                input = deviceResponse,
                verifyDocument = verifyDocument(mdocGeneratedNonce, clientId, responseUrl, expectedNonce)
            )
        }

        else -> throw IllegalArgumentException("descriptor.format: $claimFormat")
    }

    /**
     * Performs verification of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class)
    private fun verifyDocument(
        mdocGeneratedNonce: String,
        clientId: String?,
        responseUrl: String?,
        expectedNonce: String,
    ): suspend (MobileSecurityObject, Document) -> Boolean = { mso, document ->
        Napier.d(
            "verifyDocument: mdocGeneratedNonce='$mdocGeneratedNonce', clientId='$clientId'," +
                    " responseUrl='$responseUrl', expectedNonce='$expectedNonce'"
        )
        val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature
            ?: throw IllegalArgumentException("deviceSignature is null")

        val walletKey = mso.deviceKeyInfo.deviceKey
        if (clientId != null && responseUrl != null) {
            val deviceAuthentication =
                document.calcDeviceAuthentication(expectedNonce, mdocGeneratedNonce, clientId, responseUrl)
            val expectedPayload = coseCompliantSerializer
                .encodeToByteArray(coseCompliantSerializer.encodeToByteArray(deviceAuthentication))
                .wrapInCborTag(24)
                .also { Napier.d("Device authentication for verification is ${it.encodeToString(Base16())}") }
            verifyCoseSignature(deviceSignature, walletKey, byteArrayOf(), expectedPayload).onFailure {
                throw IllegalArgumentException("deviceSignature not verified", it)
            }
        } else {
            verifyCoseSignature(deviceSignature, walletKey, byteArrayOf(), null).onFailure {
                throw IllegalArgumentException("deviceSignature not verified", it)
            }
            val deviceSignaturePayload = deviceSignature.payload
                ?: throw IllegalArgumentException("challenge is null")
            if (!deviceSignaturePayload.contentEquals(expectedNonce.encodeToByteArray())) {
                throw IllegalArgumentException("challenge invalid: ${deviceSignaturePayload.encodeToString(Base16)}")
            }
        }
        true
    }

    /**
     * Performs calculation of the [at.asitplus.iso.SessionTranscript] and [at.asitplus.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024
     */
    private fun Document.calcDeviceAuthentication(
        challenge: String,
        mdocGeneratedNonce: String,
        clientId: String,
        responseUrl: String,
    ): DeviceAuthentication {
        val clientIdToHash = ClientIdToHash(clientId = clientId, mdocGeneratedNonce = mdocGeneratedNonce)
        val responseUriToHash = ResponseUriToHash(responseUri = responseUrl, mdocGeneratedNonce = mdocGeneratedNonce)
        val sessionTranscript = SessionTranscript.forOpenId(
            OID4VPHandover(
                clientIdHash = coseCompliantSerializer.encodeToByteArray(clientIdToHash).sha256(),
                responseUriHash = coseCompliantSerializer.encodeToByteArray(responseUriToHash).sha256(),
                nonce = challenge
            ),
        )
        return DeviceAuthentication(
            type = "DeviceAuthentication",
            sessionTranscript = sessionTranscript,
            docType = docType,
            namespaces = deviceSigned.namespaces
        )
    }

    private fun VerifyPresentationResult.mapToAuthnResponseResult(state: String) = when (this) {
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
    ) = run {
        val attestationJwt = (clientIdScheme as? ClientIdScheme.VerifierAttestation)?.attestationJwt?.serialize()
        (clientIdScheme as? ClientIdScheme.CertificateSanDns)?.chain?.let { x5c ->
            it.copy(certificateChain = x5c, attestationJwt = attestationJwt)
        } ?: it.copy(jsonWebKey = keyMaterial.jsonWebKey, attestationJwt = attestationJwt)
    }
}
