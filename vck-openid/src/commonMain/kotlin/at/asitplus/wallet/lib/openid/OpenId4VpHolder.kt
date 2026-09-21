package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.IdToken
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
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
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.signum.supreme.UserInitiatedCancellationReason
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationResponseParameters.*
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import com.benasher44.uuid.uuid4
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import at.asitplus.wallet.lib.agent.CredentialMatchingResult as HolderCredentialMatchingResult

/**
 * Combines Verifiable Presentations with OAuth 2.0.
 * Implements [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (1.0, 2025-07-09).
 *
 * The verifier (see [OpenId4VpVerifier]) creates the Authentication Request,
 * we can parse and validate it in [startAuthorizationResponsePreparation],
 * show the information to the user,
 * and create the response in [finalizeAuthorizationResponse], and send it back to the verifier.
 */
class OpenId4VpHolder @JvmOverloads constructor(
    /** Key material used to encrypt responses and sign ID tokens. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Holds the credentials and creates the verifiable presentation. */
    private val holder: Holder = HolderAgent(keyMaterial),
    @Deprecated("Support for SIOPv2 has been removed")
    private val signIdToken: SignJwtFun<IdToken> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    /** Encrypts the authn response to the verifier, if this has been requested. */
    private val encryptJarm: EncryptJweFun = EncryptJwe(),
    /** Advertised in [metadata] and compared against holder's requirements. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Signs the session transcript for mDoc responses. */
    @Deprecated(
        "signDeviceAuthDetached no longer has any effect because ISO Device signature" +
                "creation has been moved into Holder's credential presentation. " +
                "Signing function can be overridden in HolderAgent instead."
    )
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> =
        SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone()),
    @Deprecated("Support for SIOPv2 has been removed")
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
    @Deprecated("No longer invoked. Replace with `relyingPartyTrust` for use in `AuthorizationRequestValidator`")
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier? = null,
    /** How to establish trust in the relying party sending an authorization request, or `null` for trusting all. */
    private val relyingPartyTrust: Set<RelyingPartyTrust>? = null,
    /** Stores our nonce used when fetching authn requests using POST. */
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    /** Source for random bytes, i.e., nonces for encrypted responses. */
    private val randomSource: RandomSource = RandomSource.Secure,
    /** Callback to load encryption keys for pre-registered clients. */
    private val lookupJsonWebKeysForClient: (JsonWebKeyLookupInput) -> JsonWebKeySet? = { null },
    /**
     * Supplies the allowed schemes for origins received with OpenID4VP DC API requests.
     * Values may be normal URI scheme names or a specific platform-origin prefix. The provider
     * is invoked for every request so applications can update their policy at runtime.
     */
    private val allowedDcApiOriginSchemes: suspend () -> Set<String> = { DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES },
    /** Set to accept encrypted authorization requests fetched with a POST (when RP supports that). */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService? = null,
    /** Advertised in `wallet_metadata` to encrypt authorization requests, see [ephemeralEncryptionKeyService]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
    /** Set to reject a plain request object we have fetched with POST (when RP supports that) */
    private val requireEncryptedRequests: Boolean = false,
) {

    init {
        require(!requireEncryptedRequests || ephemeralEncryptionKeyService != null) {
            "requireEncryptedRequests needs an ephemeralEncryptionKeyService to advertise a key with"
        }
    }

    companion object {
        const val HTTPS_ORIGIN_SCHEME = "https"
        const val ANDROID_APK_KEY_HASH_ORIGIN_SCHEME = "android:apk-key-hash"
        val DEFAULT_ALLOWED_DC_API_ORIGIN_SCHEMES: Set<String> = setOf(
            HTTPS_ORIGIN_SCHEME,
            ANDROID_APK_KEY_HASH_ORIGIN_SCHEME,
        )
    }

    data class JsonWebKeyLookupInput(
        val clientId: String?
    )

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val authorizationRequestValidator = AuthorizationRequestValidator(
        walletNonceMapStore = walletNonceMapStore,
        allowedDcApiOriginSchemes = allowedDcApiOriginSchemes,
        relyingPartyTrust = relyingPartyTrust,
    )
    private val authenticationResponseFactory = AuthenticationResponseFactory(
        encryptResponse = encryptJarm,
        randomSource = randomSource
    )

    private val presentationFactory = PresentationFactory(supportedAlgorithms)

    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = clientId,
            authorizationEndpoint = authorizationEndpoint,
            responseTypesSupported = setOf(VP_TOKEN),
            requestObjectSigningAlgorithmsSupportedStrings = supportedJwsAlgorithms.toSet(),
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

    /**
     * The [metadata] to send when fetching a request object, carrying one ephemeral encryption key valid for exactly
     * that request, if [ephemeralEncryptionKeyService] is set. Must be evaluated exactly once per request.
     */
    private suspend fun metadataForRequestObject(): OAuth2AuthorizationServerMetadata =
        ephemeralEncryptionKeyService?.let {
            metadata.copy(
                jsonWebKeySet = JsonWebKeySet(listOf(it.createKey().toEncryptionJsonWebKey())),
                requestObjectEncryptionAlgValuesSupportedStrings = setOf(JweAlgorithm.ECDH_ES.identifier),
                requestObjectEncryptionEncValuesSupportedStrings = supportedJweEncryptionAlgorithms
                    .map { enc -> enc.identifier }.toSet(),
            )
        } ?: metadata

    private val requestParser = RequestParser(
        remoteResourceRetriever = remoteResourceRetriever,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        requireEncryptedRequests = requireEncryptedRequests,
    ) {
        RequestObjectParameters(
            metadata = metadataForRequestObject(),
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

    @Deprecated("Use createAuthnErrorResponse with AuthorizationResponsePreparationState parameter")
    suspend fun createAuthnErrorResponse(
        error: Throwable,
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponseResult> = catching {
        authenticationResponseFactory.createAuthenticationResponse(
            state = startAuthorizationResponsePreparation(request).getOrThrow(),
            response = AuthenticationResponse.Error(
                error = error.toOAuth2Error(request),
            )
        )
    }

    /** Creates an error response for the [error], which can be sent to the verifier / relying party. */
    suspend fun createAuthnErrorResponse(
        error: Throwable,
        state: AuthorizationResponsePreparationState,
    ): KmmResult<AuthenticationResponseResult> = catching {
        authenticationResponseFactory.createAuthenticationResponse(
            state = state,
            response = AuthenticationResponse.Error(
                error = error.toOAuth2Error(state.request)
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
        finalizeAuthorizationResponseParameters(
            state = preparationState,
        ).getOrElse {
            it.getUserSignatureCancellationException()?.let {
                throw it // DON'T create error response for user initiated signature cancellation, just expose it
            }
            return createAuthnErrorResponse(it, preparationState)
        }.let {
            authenticationResponseFactory.createAuthenticationResponse(preparationState, it)
        }
    }

    private fun Throwable.getUserSignatureCancellationException(): UserInitiatedCancellationReason? {
        var current: Throwable? = this
        while (current != null) {
            if (current is UserInitiatedCancellationReason) {
                return current // DON'T send error response for user cancellation
            }
            current = current.cause
        }
        return null
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
     * Validates the [AuthenticationRequestParameters] from [params] and loads remote objects (client metadata, keys).
     * Clients need to inform the user, get consent, and resume in [finalizeAuthorizationResponse].
     *
     * Exceptions thrown during request parsing are caught by [KmmResult],
     */
    suspend fun startAuthorizationResponsePreparation(
        params: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        authorizationRequestValidator.validateAuthorizationRequest(params)
        val loadedKeys = (params.parameters.clientMetadata?.loadJsonWebKeySet()?.keys
            ?: lookupJsonWebKeysForClient(JsonWebKeyLookupInput(params.parameters.clientId))?.keys)
        val jsonWebKeys = loadedKeys?.combine(params.extractLeafCertKey())
        AuthorizationResponsePreparationState(
            request = params,
            credentialPresentationRequest = params.parameters.loadCredentialRequest(),
            clientMetadata = params.parameters.clientMetadata,
            jsonWebKeys = jsonWebKeys,
            verifierInfo = params.parameters.verifierInfo,
            audience = params.extractAudience(jsonWebKeys)
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
            it.getUserSignatureCancellationException()?.let { userCancellationException ->
                throw userCancellationException // DON'T create error response for user initiated signature cancellation
            }
            return createAuthnErrorResponse(it, preparationState)
        }.let {
            authenticationResponseFactory.createAuthenticationResponse(preparationState, it)
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
            val presentation = credentialPresentation ?: credentialPresentationRequest?.toCredentialPresentation()
            val resultContainer = presentation?.let {
                presentationFactory.createPresentation(
                    state = state,
                    holder = holder,
                    credentialPresentation = presentation
                ).getOrThrow()
            }

            val parameters = AuthenticationResponseParameters(
                state = request.parameters.state,
                vpToken = when (resultContainer) {
                    null -> null
                    is DCQLParameters -> resultContainer.vpToken
                    is PresentationExchangeParameters -> resultContainer.vpToken
                    is DeviceRetrievalParameters ->
                        throw InvalidRequest("ISO Device Retrieval responses are not OpenID4VP presentations")
                },
            )
            AuthenticationResponse.Success(
                params = parameters
            )
        }
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.extractLeafCertKey(): JsonWebKey? =
        (this as? RequestParametersFrom.Jws<AuthenticationRequestParameters>)?.jws?.let {
            (it as? JwsCompact)?.jwsHeader?.certificateChain?.firstOrNull()?.decodedPublicKey?.getOrNull()
                ?.toJsonWebKey()
        }

    /**
     * Matches the presentation request from [preparationState] against the holder's available credentials.
     *
     * This only returns candidates for wallet UI and consent; it neither selects a submission nor creates or signs a
     * response. Turn the chosen candidates into a [CredentialPresentation] and pass it to
     * [finalizeAuthorizationResponse]. The returned subtype mirrors the request language so its selection rules stay
     * available to the caller.
     *
     * Credentials preselected by a DC API request are applied as a store filter.
     */
    suspend fun getMatchingCredentials(
        preparationState: AuthorizationResponsePreparationState,
    ): KmmResult<HolderCredentialMatchingResult<SubjectCredentialStore.StoreEntry>> = catching {
        val presentationRequest = preparationState.credentialPresentationRequest
            ?: throw InvalidRequest("No credential presentation request is available")
        holder.matchPresentationRequestAgainstCredentialStore(
            presentationRequest = presentationRequest,
            filterByIds = preparationState.request.credentialIds(),
        ).getOrThrow()
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
        is RequestParametersFrom.DcApiRequest -> "origin:$callingOrigin"
        else -> parameters.clientId
            ?: parameters.issuer
            ?: clientJsonWebKeySet?.firstOrNull()
                ?.let { it.keyId ?: it.didEncoded ?: it.jwkThumbprint }
            ?: throw InvalidRequest("could not parse audience")
    }

    private fun RequestParametersFrom<AuthenticationRequestParameters>.credentialIds() =
        (this as? RequestParametersFrom.DcApiRequest)?.credentialIds

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet(): JsonWebKeySet? =
        jsonWebKeySet ?: jsonWebKeySetUrl
            ?.let { remoteResourceRetriever(RemoteResourceRetrieverInput(it)) }
            ?.let { joseCompliantSerializer.decodeFromString(it) }

    private suspend fun AuthenticationRequestParameters.loadCredentialRequest(): CredentialPresentationRequest? =
        if (responseType?.contains(VP_TOKEN) == true) {
            dcqlQuery?.let { CredentialPresentationRequest.DCQLRequest(it) }
        } else null

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
    is RequestParametersFrom.IsoMdocDcApi.IsoMdocRequestWrapper -> null
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
