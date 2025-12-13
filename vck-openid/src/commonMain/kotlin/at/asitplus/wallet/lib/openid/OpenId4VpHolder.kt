package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.request.DCAPIWalletRequest
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.openid.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.openid.SupportedAlgorithmsContainerIso
import at.asitplus.openid.SupportedAlgorithmsContainerJwt
import at.asitplus.openid.SupportedAlgorithmsContainerSdJwt
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import com.benasher44.uuid.uuid4
import kotlin.time.Clock

/**
 * Combines Verifiable Presentations with OAuth 2.0.
 * Implements [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (1.0, 2025-07-09)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (D13, 2023-11-28).
 *
 * The verifier (see [OpenId4VpVerifier]) creates the Authentication Request,
 * we can parse and validate it in [startAuthorizationResponsePreparation],
 * show the information to the user,
 * and create the response in [finalizeAuthorizationResponse], and send it back to the verifier.
 */
class OpenId4VpHolder(
    /** Key material used to encrypt responses and sign ID tokens. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Holds the credentials and creates the verifiable presentation. */
    private val holder: Holder = HolderAgent(keyMaterial),
    /** Signs the ID token for SIOPv2 responses. */
    private val signIdToken: SignJwtFun<IdToken> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    /** Encrypts the authn response to the holder using [keyMaterial], if requested. */
    private val encryptJarm: EncryptJweFun = EncryptJwe(keyMaterial),
    /** Advertised in [metadata] and compared against holder's requirements. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Signs the session transcript for mDoc responses. */
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> =
        SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone()),
    /** Clock used for the signed ID token. */
    private val clock: Clock = Clock.System,
    /** Advertised as `issuer` in [metadata]. */
    private val clientId: String = "https://wallet.a-sit.at/",
    /** Advertised as `authorization_endpoint` in [metadata]. */
    private val authorizationEndpoint: String = "openid4vp:",
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [ClientIdScheme.PreRegistered]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _ -> true },
    /** Stores our nonce used when fetching authn requests using POST. */
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    /** Source for random bytes, i.e., nonces for encrypted responses. */
    private val randomSource: RandomSource = RandomSource.Secure,
    /** Callback to load encryption keys for pre-registered clients. */
    private val lookupJsonWebKeysForClient: (JsonWebKeyLookupInput) -> JsonWebKeySet? = { null }
) {

    data class JsonWebKeyLookupInput(
        val clientId: String?
    )

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val authorizationRequestValidator = AuthorizationRequestValidator(walletNonceMapStore)
    private val authenticationResponseFactory = AuthenticationResponseFactory(
        encryptResponse = encryptJarm,
        randomSource = randomSource
    )
    private val presentationFactory = PresentationFactory(
        supportedAlgorithms = supportedAlgorithms,
        signDeviceAuthDetached = signDeviceAuthDetached,
        signIdToken = signIdToken,
        randomSource = randomSource
    )

    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = clientId,
            authorizationEndpoint = authorizationEndpoint,
            responseTypesSupported = setOf(OpenIdConstants.ID_TOKEN, OpenIdConstants.VP_TOKEN),
            scopesSupported = setOf(OpenIdConstants.SCOPE_OPENID),
            idTokenSigningAlgorithmsSupportedStrings = supportedJwsAlgorithms.toSet(),
            requestObjectSigningAlgorithmsSupportedStrings = supportedJwsAlgorithms.toSet(),
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY, BINDING_METHOD_JWK),
            idTokenTypesSupported = setOf(IdTokenType.SUBJECT_SIGNED),
            presentationDefinitionUriSupported = false,
            clientIdPrefixesSupported = listOf(
                ClientIdScheme.PreRegistered,
                ClientIdScheme.RedirectUri,
                ClientIdScheme.VerifierAttestation,
                ClientIdScheme.X509SanDns,
                ClientIdScheme.X509Hash
            ).map { it.stringRepresentation }.toSet(),
            responseModesSupported = OpenIdConstants.ResponseMode.entries.map { it.stringRepresentation }.toSet(),
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

    private val requestParser: RequestParser =
        RequestParser(remoteResourceRetriever, requestObjectJwsVerifier) {
            RequestObjectParameters(
                metadata = metadata,
                nonce = uuid4().toString().also { walletNonceMapStore.put(it, it) })
        }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseResult] that can be sent back to the Verifier.
     *
     * Exceptions thrown during request parsing are caught by [KmmResult],
     * exceptions during request handling result in the [AuthenticationResponseResult] containing the [OAuth2Error].
     */
    suspend fun createAuthnResponse(
        input: String,
    ): KmmResult<AuthenticationResponseResult> = catching {
        createAuthnResponse(parse(input)).getOrThrow()
    }

    @Suppress("UNCHECKED_CAST")
    private suspend fun parse(
        input: String,
    ) = requestParser.parseRequestParameters(input)
        .getOrThrow() as RequestParametersFrom<AuthenticationRequestParameters>

    @Suppress("UNCHECKED_CAST")
    private suspend fun parse(
        input: DCAPIWalletRequest.OpenId4Vp,
    ) = requestParser.parseRequestParameters(input)
        .getOrThrow() as RequestParametersFrom<AuthenticationRequestParameters>

    /** Creates an error response for the [error], which can be sent to the verifier / relying party. */
    suspend fun createAuthnErrorResponse(
        error: Throwable,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponseResult> = catching {
        authenticationResponseFactory.createAuthenticationResponse(
            request = request,
            response = AuthenticationResponse.Error(
                error = error.toOAuth2Error(request),
                clientMetadata = request.parameters.clientMetadata,
                jsonWebKeys = request.parameters.clientMetadata?.loadJsonWebKeySet()?.keys
                    ?: lookupJsonWebKeysForClient(JsonWebKeyLookupInput(request.parameters.clientId))?.keys,
            )
        )
    }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     *
     * Exceptions thrown during wrapping the response are caught by [KmmResult],
     * exceptions during request handling result in the [AuthenticationResponseResult] containing the [OAuth2Error].
     */
    suspend fun createAuthnResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponseResult> = catching {
        val preparationState = startAuthorizationResponsePreparation(request).getOrThrow()
        if (preparationState.requestObjectVerified == false)
            throw InvalidRequest("Request object verification failed")
        finalizeAuthorizationResponseParameters(
            state = preparationState,
        ).getOrElse {
            return createAuthnErrorResponse(it, preparationState.request)
        }.let {
            authenticationResponseFactory.createAuthenticationResponse(preparationState.request, it)
        }
    }

    /**
     * Parses the [AuthenticationRequestParameters] from [input] and loads remote objects (client metadata, keys).
     * Clients need to inform the user, get consent, and resume in [finalizeAuthorizationResponse].
     *
     * Exceptions thrown during request parsing are caught by [KmmResult],
     */
    suspend fun startAuthorizationResponsePreparation(
        input: String,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        startAuthorizationResponsePreparation(parse(input)).getOrThrow()
    }

    /**
     * Loads the [AuthenticationRequestParameters] from DC API [input].
     * Clients need to inform the user, get consent, and resume in [finalizeAuthorizationResponse].
     *
     * Exceptions thrown during request parsing are caught by [KmmResult],
     */
    suspend fun startAuthorizationResponsePreparation(
        input: DCAPIWalletRequest.OpenId4Vp,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        startAuthorizationResponsePreparation(parse(input)).getOrThrow()
    }

    /**
     * Validates the [AuthenticationRequestParameters] from [params] and loads remote objects (client metadata, keys).
     * Clients need to inform the user, get consent, and resume in [finalizeAuthorizationResponse].
     *
     * Exceptions thrown during request parsing are caught by [KmmResult],
     */
    suspend fun startAuthorizationResponsePreparation(
        params: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        authorizationRequestValidator.validateAuthorizationRequest(params)
        AuthorizationResponsePreparationState(
            request = params,
            credentialPresentationRequest = params.parameters.loadCredentialRequest(),
            clientMetadata = params.parameters.clientMetadata,
            jsonWebKeys = params.parameters.clientMetadata?.loadJsonWebKeySet()?.keys
                ?: lookupJsonWebKeysForClient(JsonWebKeyLookupInput(params.parameters.clientId))?.keys,
            requestObjectVerified = (params as? RequestParametersFrom.JwsSigned)?.verified,
            verifierInfo = params.parameters.verifierInfo
        )
    }

    /**
     * Finalize the authorization response, given the [preparationState] from [startAuthorizationResponsePreparation],
     * and the [credentialPresentation] selected by the user.
     */
    suspend fun finalizeAuthorizationResponse(
        preparationState: AuthorizationResponsePreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<AuthenticationResponseResult> = catching {
        finalizeAuthorizationResponseParameters(
            state = preparationState,
            credentialPresentation = credentialPresentation
        ).getOrElse {
            return createAuthnErrorResponse(it, preparationState.request)
        }.let {
            authenticationResponseFactory.createAuthenticationResponse(preparationState.request, it)
        }
    }

    /**
     * Finalize the authorization response parameters
     *
     * @param state from [startAuthorizationResponsePreparation]
     * @param credentialPresentation the credentials that are actually being used for the VP
     */
    private suspend fun finalizeAuthorizationResponseParameters(
        state: AuthorizationResponsePreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<AuthenticationResponse> = catching {
        with(state) {
            val audience = request.extractAudience(jsonWebKeys)
            val jsonWebKeys = jsonWebKeys?.combine(request.extractLeafCertKey())
                ?: lookupJsonWebKeysForClient(JsonWebKeyLookupInput(request.parameters.clientId))?.keys
            val idToken = presentationFactory.createSignedIdToken(clock, keyMaterial.publicKey, request)
                .getOrNull()?.serialize()
            val presentation = credentialPresentation ?: credentialPresentationRequest?.toCredentialPresentation()
            val resultContainer = presentation?.let {
                presentationFactory.createPresentation(
                    holder = holder,
                    request = request.parameters,
                    audience = audience,
                    nonce = request.parameters.nonce!!,
                    credentialPresentation = presentation,
                    clientMetadata = clientMetadata,
                    jsonWebKeys = jsonWebKeys,
                    dcApiRequestCallingOrigin = request.callingOrigin()
                ).getOrThrow()
            }

            val parameters = AuthenticationResponseParameters(
                state = request.parameters.state,
                idToken = idToken,
                vpToken = resultContainer?.vpToken,
                presentationSubmission = resultContainer?.presentationSubmission,
            )
            AuthenticationResponse.Success(
                params = parameters,
                clientMetadata = clientMetadata,
                jsonWebKeys = jsonWebKeys
            )
        }
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.extractLeafCertKey(): JsonWebKey? =
        (this as? RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>)
            ?.jwsSigned?.header?.certificateChain?.firstOrNull()?.decodedPublicKey?.getOrNull()?.toJsonWebKey()

    suspend fun getMatchingCredentials(
        preparationState: AuthorizationResponsePreparationState,
    ) = catchingUnwrapped {
        when (val it = preparationState.credentialPresentationRequest) {
            is CredentialPresentationRequest.DCQLRequest ->
                DCQLMatchingResult(
                    presentationRequest = it,
                    dcqlQueryResult = holder.matchDCQLQueryAgainstCredentialStore(
                        dcqlQuery = it.dcqlQuery,
                        filterById = preparationState.request.credentialId()
                    ).getOrThrow()
                )

            is CredentialPresentationRequest.PresentationExchangeRequest ->
                holder.matchInputDescriptorsAgainstCredentialStore(
                    inputDescriptors = it.presentationDefinition.inputDescriptors,
                    fallbackFormatHolder = it.fallbackFormatHolder,
                    filterById = preparationState.request.credentialId()
                ).getOrThrow().let { matchInputDescriptors ->
                    if (matchInputDescriptors.values.find { it.size != 0 } == null) {
                        throw OAuth2Exception.AccessDenied("No matching credential")
                    } else {
                        PresentationExchangeMatchingResult(
                            presentationRequest = it,
                            matchingInputDescriptorCredentials = matchInputDescriptors
                        )
                    }
                }

            null -> TODO()
        }
    }

    /**
     * DC API:
     * The audience for the response (for example, the `aud` value in a Key Binding JWT) MUST be the
     * Origin, prefixed with `origin:`, for example `origin:https://verifier.example.com/`.
     * This is the case even for signed requests. Therefore, when using OpenID4VP over the DC API,
     * the Client Identifier is not used as the audience for the response.
     */
    @Throws(OAuth2Exception::class)
    private fun RequestParametersFrom<AuthenticationRequestParameters>.extractAudience(
        clientJsonWebKeySet: Collection<JsonWebKey>?,
    ) = when (this) {
        is RequestParametersFrom.DcApiSigned<*> -> "origin:${dcApiRequest.callingOrigin}"
        is RequestParametersFrom.DcApiUnsigned<*> -> "origin:${dcApiRequest.callingOrigin}"
        is RequestParametersFrom.Json<*> -> parameters.extractAudience(clientJsonWebKeySet)
        is RequestParametersFrom.JwsSigned<*> -> parameters.extractAudience(clientJsonWebKeySet)
        is RequestParametersFrom.Uri<*> -> parameters.extractAudience(clientJsonWebKeySet)
    }

    @Throws(OAuth2Exception::class)
    private fun AuthenticationRequestParameters.extractAudience(
        clientJsonWebKeySet: Collection<JsonWebKey>?,
    ) = clientId
        ?: issuer
        ?: clientJsonWebKeySet?.firstOrNull()
            ?.let { it.keyId ?: it.didEncoded ?: it.jwkThumbprint }
        ?: throw InvalidRequest("could not parse audience")

    private fun RequestParametersFrom<AuthenticationRequestParameters>.callingOrigin() = when (this) {
        is RequestParametersFrom.DcApiSigned<*> -> dcApiRequest.callingOrigin
        is RequestParametersFrom.DcApiUnsigned<*> -> dcApiRequest.callingOrigin
        else -> null
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.credentialId() = when (this) {
        is RequestParametersFrom.DcApiSigned<*> -> dcApiRequest.credentialId
        is RequestParametersFrom.DcApiUnsigned<*> -> dcApiRequest.credentialId
        else -> null
    }

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet(): JsonWebKeySet? =
        jsonWebKeySet ?: jsonWebKeySetUrl
            ?.let { remoteResourceRetriever(RemoteResourceRetrieverInput(it)) }
            ?.let { joseCompliantSerializer.decodeFromString(it) }

    private suspend fun AuthenticationRequestParameters.loadCredentialRequest(): CredentialPresentationRequest? =
        if (responseType?.contains(VP_TOKEN) == true) {
            loadPresentationDefinition()?.let { CredentialPresentationRequest.PresentationExchangeRequest(it) }
                ?: dcqlQuery?.let { CredentialPresentationRequest.DCQLRequest(it) }
        } else null

    private suspend fun AuthenticationRequestParameters.loadPresentationDefinition(): PresentationDefinition? =
        presentationDefinition ?: presentationDefinitionUrl
            ?.let { remoteResourceRetriever(RemoteResourceRetrieverInput(it)) }
            ?.let { vckJsonSerializer.decodeFromString(it) }

}

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> =
    certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()

fun Throwable.toOAuth2Error(
    request: RequestParametersFrom<*>,
): OAuth2Error = toOAuth2Error(state = request.parameters.state())

private fun RequestParameters.state() = when (this) {
    is AuthenticationRequestParameters -> this.state
    is JarRequestParameters -> this.state
    is RequestObjectParameters -> null
    is SignatureRequestParameters -> this.state
}

fun Throwable.toOAuth2Error(
    state: String?,
): OAuth2Error = when (this) {
    is OAuth2Exception -> this.toOAuth2Error().copy(state = state)
    else -> OAuth2Error(
        error = INVALID_REQUEST,
        errorDescription = message,
        state = state
    )
}