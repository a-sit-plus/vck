package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.IdTokenType
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.BINDING_METHOD_JWK
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.ID_TOKEN
import at.asitplus.openid.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParameters
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.CredentialSubmission
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.helper.AuthenticationResponseFactory
import at.asitplus.wallet.lib.oidc.helper.AuthorizationRequestValidator
import at.asitplus.wallet.lib.oidc.helper.PresentationFactory
import at.asitplus.wallet.lib.oidc.helper.RequestParser
import at.asitplus.wallet.lib.oidc.helpers.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * The [holder] creates the Authentication Response, see [OidcSiopVerifier] for the verifier.
 */
class OidcSiopWallet(
    private val holder: Holder,
    private val agentPublicKey: CryptoPublicKey,
    private val jwsService: JwsService,
    private val clock: Clock = Clock.System,
    private val clientId: String = "https://wallet.a-sit.at/",
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction,
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PreRegistered]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier,
    /**
     * Need to implement if the presentation definition needs to be derived from a scope value.
     * See [ScopePresentationDefinitionRetriever] for implementation instructions.
     */
    private val scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever,
    /**
     * Used to resolve [RequestParameters] by reference and also matches them to the correct [RequestParametersFrom]
     */
    private val requestParser: RequestParser,
) {
    constructor(
        keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
        holder: Holder = HolderAgent(keyMaterial),
        jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
        clock: Clock = Clock.System,
        clientId: String = "https://wallet.a-sit.at/",
        /**
         * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
         * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
         * Implementations need to fetch the url passed in, and return either the body, if there is one,
         * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
         */
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
        /**
         * Need to verify the request object serialized as a JWS,
         * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PreRegistered]).
         */
        requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _ -> true },
        /**
         * Need to implement if the presentation definition needs to be derived from a scope value.
         * See [ScopePresentationDefinitionRetriever] for implementation instructions.
         */
        scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever = { null },
        requestParser: RequestParser = RequestParser(
            remoteResourceRetriever = remoteResourceRetriever,
            requestObjectJwsVerifier = requestObjectJwsVerifier,
        ),
    ) : this(
        holder = holder,
        agentPublicKey = keyMaterial.publicKey,
        jwsService = jwsService,
        clock = clock,
        clientId = clientId,
        remoteResourceRetriever = remoteResourceRetriever,
        requestObjectJwsVerifier = requestObjectJwsVerifier,
        scopePresentationDefinitionRetriever = scopePresentationDefinitionRetriever,
        requestParser = requestParser,
    )

    val metadata: OAuth2AuthorizationServerMetadata by lazy {
        OAuth2AuthorizationServerMetadata(
            issuer = clientId,
            authorizationEndpoint = clientId,
            responseTypesSupported = setOf(ID_TOKEN),
            scopesSupported = setOf(SCOPE_OPENID),
            subjectTypesSupported = setOf("pairwise", "public"),
            idTokenSigningAlgorithmsSupportedStrings = setOf(jwsService.algorithm.identifier),
            requestObjectSigningAlgorithmsSupportedStrings = setOf(jwsService.algorithm.identifier),
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY, BINDING_METHOD_JWK),
            idTokenTypesSupported = setOf(IdTokenType.SUBJECT_SIGNED),
            presentationDefinitionUriSupported = false,
        )
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseResult] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun createAuthnResponse(input: String): KmmResult<AuthenticationResponseResult> =
        catching {
            createAuthnResponse(parseAuthenticationRequestParameters(input).getOrThrow()).getOrThrow()
        }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<RequestParametersFrom<AuthenticationRequestParameters>> =
        catching {
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
            AuthenticationResponseFactory(jwsService).createAuthenticationResponse(request, it)
        }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: RequestParametersFrom<AuthenticationRequestParameters>,
    ): KmmResult<AuthenticationResponse> = startAuthorizationResponsePreparation(params).map {
        finalizeAuthorizationResponseParameters(
            request = params,
            preparationState = it,
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
        val presentationDefinition = params.parameters.loadPresentationDefinition()
        AuthorizationRequestValidator().validateAuthorizationRequest(params)
        AuthorizationResponsePreparationState(presentationDefinition, clientMetadata)
    }

    /**
     * Finalize the authorization response
     *
     * @param request the parsed authentication request
     * @param preparationState The preparation state from [startAuthorizationResponsePreparation]
     * @param inputDescriptorSubmissions Map from input descriptor ids to [CredentialSubmission]
     */
    suspend fun finalizeAuthorizationResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        preparationState: AuthorizationResponsePreparationState,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponseResult> = finalizeAuthorizationResponseParameters(
        request,
        preparationState,
        inputDescriptorSubmissions,
    ).map { responseParameters ->
        AuthenticationResponseFactory(jwsService).createAuthenticationResponse(
            request,
            responseParameters,
        )
    }


    /**
     * Finalize the authorization response parameters
     *
     * @param request the parsed authentication request
     * @param preparationState The preparation state from [startAuthorizationResponsePreparation]
     * @param inputDescriptorSubmissions Map from input descriptor ids to [CredentialSubmission]
     */
    suspend fun finalizeAuthorizationResponseParameters(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        preparationState: AuthorizationResponsePreparationState,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponse> = preparationState.catching {
        val certKey = (request as? RequestParametersFrom.JwsSigned<AuthenticationRequestParameters>)
            ?.jwsSigned?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val clientJsonWebKeySet = clientMetadata?.loadJsonWebKeySet()
        val audience = request.extractAudience(clientJsonWebKeySet)
        val presentationFactory = PresentationFactory(jwsService)
        val idToken = presentationFactory.createSignedIdToken(
            clock = clock,
            agentPublicKey = agentPublicKey,
            request = request,
        ).getOrNull()?.serialize()

        val resultContainer = presentationDefinition?.let {
            presentationFactory.createPresentationExchangePresentation(
                holder = holder,
                request = request,
                audience = audience,
                presentationDefinition = presentationDefinition,
                clientMetadata = clientMetadata,
                inputDescriptorSubmissions = inputDescriptorSubmissions
            ).getOrThrow()
        }
        val vpToken = resultContainer?.presentationResults?.map { it.toJsonPrimitive() }?.singleOrArray()
        val presentationSubmission = resultContainer?.presentationSubmission
        val parameters = AuthenticationResponseParameters(
            state = request.parameters.state,
            idToken = idToken,
            vpToken = vpToken,
            presentationSubmission = presentationSubmission,
        )
        val jsonWebKeys = clientJsonWebKeySet?.keys?.combine(certKey)
        AuthenticationResponse(parameters, clientMetadata, jsonWebKeys)
    }

    @Throws(OAuth2Exception::class)
    private fun RequestParametersFrom<AuthenticationRequestParameters>.extractAudience(
        clientJsonWebKeySet: JsonWebKeySet?,
    ) = clientJsonWebKeySet?.keys?.firstOrNull()
        ?.let { it.keyId ?: it.didEncoded ?: it.jwkThumbprint }
        ?: parameters.clientId
        ?: parameters.audience
        ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("Could not parse audience") }

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet() =
        this.jsonWebKeySet ?: jsonWebKeySetUrl?.let { remoteResourceRetriever.invoke(it) }
            ?.let { JsonWebKeySet.deserialize(it).getOrNull() }


    private suspend fun AuthenticationRequestParameters.loadPresentationDefinition() =
        if (responseType?.contains(VP_TOKEN) == true) {
            presentationDefinition ?: presentationDefinitionUrl?.let {
                remoteResourceRetriever.invoke(it)
            }?.let { PresentationDefinition.deserialize(it).getOrNull() } ?: scope?.split(" ")
                ?.firstNotNullOfOrNull {
                    scopePresentationDefinitionRetriever.invoke(it)
                }
        } else null

    private suspend fun AuthenticationRequestParameters.loadClientMetadata() =
        clientMetadata ?: clientMetadataUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
        }

    /**
     * Source for logic:  Appendix A. Credential Format Profiles in
     * [OID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A)
     */
    private fun Holder.CreatePresentationResult.toJsonPrimitive() = when (this) {
        is Holder.CreatePresentationResult.Signed -> JsonPrimitive(jws)
        is Holder.CreatePresentationResult.SdJwt -> JsonPrimitive(sdJwt)
        is Holder.CreatePresentationResult.DeviceResponse ->
            JsonPrimitive(deviceResponse.serialize().encodeToString(Base64UrlStrict))
    }

    private fun List<JsonPrimitive>.singleOrArray() = if (size == 1) {
        this[0]
    } else buildJsonArray {
        forEach { add(it) }
    }
}

/**
 * Implementations need to fetch the url passed in, and return either the body, if there is one,
 * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
 */
typealias RemoteResourceRetrieverFunction = suspend (String) -> String?

/**
 * Implementations need to match a scope value to a [PresentationDefinition] if a related
 * presentation definition is known.
 */
typealias ScopePresentationDefinitionRetriever = suspend (String) -> PresentationDefinition?

/**
 * Implementations need to verify the passed [JwsSigned] and return its result
 */
fun interface RequestObjectJwsVerifier {
    operator fun invoke(jws: JwsSigned<RequestParameters>): Boolean
}

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> {
    return certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
}
