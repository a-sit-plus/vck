package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.ClientIdScheme
import at.asitplus.openid.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.RequestObjectJwsVerifier
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock

/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OpenID for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2024-12-02)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-11-28).
 *
 * The [holder] creates the Authentication Response, see [OpenId4VpVerifier] for the verifier.
 */
class OpenId4VpHolder(
    private val holder: Holder,
    private val agentPublicKey: CryptoPublicKey,
    private val jwsService: JwsService,
    private val coseService: CoseService,
    private val clock: Clock = Clock.System,
    private val clientId: String = "https://wallet.a-sit.at/",
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction,
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [ClientIdScheme.PreRegistered]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier,
    private val walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
) {
    constructor(
        keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
        holder: Holder = HolderAgent(keyMaterial),
        jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
        coseService: CoseService = DefaultCoseService(DefaultCryptoService(keyMaterial)),
        clock: Clock = Clock.System,
        clientId: String = "https://wallet.a-sit.at/",
        /**
         * Need to implement if resources are defined by reference, i.e. the URL for a [at.asitplus.signum.indispensable.josef.JsonWebKeySet],
         * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
         * Implementations need to fetch the url passed in, and return either the body, if there is one,
         * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
         */
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
        /**
         * Need to verify the request object serialized as a JWS,
         * which may be signed with a pre-registered key (see [ClientIdScheme.PreRegistered]).
         */
        requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _ -> true },
        walletNonceMapStore: MapStore<String, String> = DefaultMapStore(),
    ) : this(
        holder = holder,
        agentPublicKey = keyMaterial.publicKey,
        jwsService = jwsService,
        coseService = coseService,
        clock = clock,
        clientId = clientId,
        remoteResourceRetriever = remoteResourceRetriever,
        requestObjectJwsVerifier = requestObjectJwsVerifier,
        walletNonceMapStore = walletNonceMapStore
    )

    private val supportedAlgorithmsStrings = setOf(jwsService.algorithm.identifier)
    private val authorizationRequestValidator = AuthorizationRequestValidator(walletNonceMapStore)
    private val authenticationResponseFactory = AuthenticationResponseFactory(jwsService)

    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = clientId,
            authorizationEndpoint = clientId,
            responseTypesSupported = setOf(OpenIdConstants.ID_TOKEN),
            scopesSupported = setOf(OpenIdConstants.SCOPE_OPENID),
            subjectTypesSupported = setOf("pairwise", "public"),
            idTokenSigningAlgorithmsSupportedStrings = supportedAlgorithmsStrings,
            requestObjectSigningAlgorithmsSupportedStrings = supportedAlgorithmsStrings,
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY, BINDING_METHOD_JWK),
            idTokenTypesSupported = setOf(IdTokenType.SUBJECT_SIGNED),
            presentationDefinitionUriSupported = false,
            clientIdSchemesSupported = listOf(
                ClientIdScheme.PreRegistered,
                ClientIdScheme.RedirectUri,
                ClientIdScheme.VerifierAttestation,
                ClientIdScheme.X509SanDns,
                ClientIdScheme.X509SanUri,
            ).map { it.stringRepresentation }.toSet(),
            vpFormatsSupported = VpFormatsSupported(
                vcJwt = SupportedAlgorithmsContainer(supportedAlgorithmsStrings = supportedAlgorithmsStrings),
                vcSdJwt = SupportedAlgorithmsContainer(supportedAlgorithmsStrings = supportedAlgorithmsStrings),
                dcSdJwt = SupportedAlgorithmsContainer(supportedAlgorithmsStrings = supportedAlgorithmsStrings),
                msoMdoc = SupportedAlgorithmsContainer(
                    supportedAlgorithmsStrings = setOfNotNull(
                        coseService.algorithm.toJwsAlgorithm().getOrNull()?.identifier
                    )
                ),
            )
        )
    }

    /**
     * Used to resolve [at.asitplus.openid.RequestParameters] by reference and also matches them to the correct [at.asitplus.openid.RequestParametersFrom]
     */
    private val requestParser: RequestParser = RequestParser(remoteResourceRetriever, requestObjectJwsVerifier) {
        RequestObjectParameters(metadata, uuid4().toString().also { walletNonceMapStore.put(it, it) })
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [at.asitplus.openid.AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseResult] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun createAuthnResponse(input: String): KmmResult<AuthenticationResponseResult> =
        catching {
            createAuthnResponse(parseAuthenticationRequestParameters(input).getOrThrow()).getOrThrow()
        }

    /**
     * Pass in the URL sent by the Verifier (containing the [at.asitplus.openid.AuthenticationRequestParameters] as query parameters),
     * to create [at.asitplus.openid.AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<RequestParametersFrom<AuthenticationRequestParameters>> =
        catching {
            @Suppress("UNCHECKED_CAST")
            requestParser.parseRequestParameters(input)
                .getOrThrow() as RequestParametersFrom<AuthenticationRequestParameters>
        }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     */
    suspend fun createAuthnResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponseResult> =
        createAuthnResponseParams(request).map {
            authenticationResponseFactory.createAuthenticationResponse(request, it)
        }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponse> =
        startAuthorizationResponsePreparation(params).map {
            finalizeAuthorizationResponseParameters(
                request = params,
                clientMetadata = it.clientMetadata,
                credentialPresentation = it.credentialPresentationRequest?.toCredentialPresentation()
            ).getOrThrow()
        }

    /**
     * Starts the authorization response building process from the RP's authentication request in [input]
     */
    suspend fun startAuthorizationResponsePreparation(
        input: String,
    ): KmmResult<AuthorizationResponsePreparationState> =
        parseAuthenticationRequestParameters(input).map {
            startAuthorizationResponsePreparation(it).getOrThrow()
        }

    /**
     * Starts the authorization response building process from the RP's authentication request in [params]
     */
    suspend fun startAuthorizationResponsePreparation(
        params: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        val clientMetadata = params.parameters.loadClientMetadata()
        val presentationDefinition = params.parameters.loadCredentialRequest()
        authorizationRequestValidator.validateAuthorizationRequest(params)
        AuthorizationResponsePreparationState(presentationDefinition, clientMetadata)
    }

    /**
     * Finalize the authorization response
     *
     * @param request the parsed authentication request
     */
    suspend fun finalizeAuthorizationResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        clientMetadata: RelyingPartyMetadata?,
        credentialPresentation: CredentialPresentation?,
    ): KmmResult<AuthenticationResponseResult> =
        finalizeAuthorizationResponseParameters(request, clientMetadata, credentialPresentation).map {
            authenticationResponseFactory.createAuthenticationResponse(request, it)
        }

    /**
     * Finalize the authorization response parameters
     *
     * @param request the parsed authentication request
     */
    suspend fun <T : RequestParameters> finalizeAuthorizationResponseParameters(
        request: RequestParametersFrom<T>,
        clientMetadata: RelyingPartyMetadata?,
        credentialPresentation: CredentialPresentation?,
    ): KmmResult<AuthenticationResponse> = catching {
        @Suppress("UNCHECKED_CAST") val certKey =
            (request as? RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>)
                ?.jwsSigned?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val clientJsonWebKeySet = clientMetadata?.loadJsonWebKeySet()
        val audience = request.parameters.extractAudience(clientJsonWebKeySet)
        val presentationFactory = PresentationFactory(jwsService, coseService)
        val jsonWebKeys = clientJsonWebKeySet?.keys?.combine(certKey)
        val idToken = presentationFactory.createSignedIdToken(clock, agentPublicKey, request).getOrNull()?.serialize()

        val resultContainer = credentialPresentation?.let {
            presentationFactory.createPresentation(
                holder = holder,
                request = request.parameters,
                audience = audience,
                nonce = request.parameters.nonce!!,
                credentialPresentation = credentialPresentation,
                clientMetadata = clientMetadata,
                jsonWebKeys = jsonWebKeys,
            ).getOrThrow()
        }

        val parameters = AuthenticationResponseParameters(
            state = request.parameters.state,
            idToken = idToken,
            vpToken = resultContainer?.vpToken,
            presentationSubmission = resultContainer?.presentationSubmission,
        )
        AuthenticationResponse(
            parameters,
            clientMetadata,
            jsonWebKeys,
            resultContainer?.mdocGeneratedNonce
        )
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParameters.extractAudience(
        clientJsonWebKeySet: JsonWebKeySet?,
    ) = clientId
        ?: issuer
        ?: clientJsonWebKeySet?.keys?.firstOrNull()
            ?.let { it.keyId ?: it.didEncoded ?: it.jwkThumbprint }
        ?: throw InvalidRequest("could not parse audience")
            .also { Napier.w("Could not parse audience") }

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet() =
        jsonWebKeySet
            ?: jsonWebKeySetUrl?.let {
                remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(it))
                    ?.let { JsonWebKeySet.deserialize(it).getOrNull() }
            }

    private suspend fun AuthenticationRequestParameters.loadCredentialRequest(): CredentialPresentationRequest? =
        if (responseType?.contains(VP_TOKEN) == true) {
            run {
                presentationDefinition ?: presentationDefinitionUrl
                    ?.let { remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(it)) }
                    ?.let { PresentationDefinition.deserialize(it).getOrNull() }
            }?.let {
                CredentialPresentationRequest.PresentationExchangeRequest(it)
            } ?: dcqlQuery?.let { CredentialPresentationRequest.DCQLRequest(it) }
        } else null

    private suspend fun AuthenticationRequestParameters.loadClientMetadata() =
        clientMetadata
            ?: clientMetadataUri?.let {
                remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(it))
                    ?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
            }
}

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> =
    certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
