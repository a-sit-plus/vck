package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.CredentialSubmission
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidc.helper.AuthenticationRequestParser
import at.asitplus.wallet.lib.oidc.helper.AuthenticationResponseFactory
import at.asitplus.wallet.lib.oidc.helper.AuthorizationRequestValidator
import at.asitplus.wallet.lib.oidc.helper.PresentationFactory
import at.asitplus.wallet.lib.oidc.helpers.AuthorizationResponsePreparationState
import at.asitplus.wallet.lib.oidvci.IssuerMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
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
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PRE_REGISTERED]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier,
    /**
     * Need to implement if the presentation definition needs to be derived from a scope value.
     * See [ScopePresentationDefinitionRetriever] for implementation instructions.
     */
    private val scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever,
) {
    companion object {
        fun newDefaultInstance(
            keyPairAdapter: KeyPairAdapter = RandomKeyPairAdapter(),
            holder: Holder = HolderAgent(keyPairAdapter),
            jwsService: JwsService = DefaultJwsService(
                DefaultCryptoService(keyPairAdapter)
            ),
            clock: Clock = Clock.System,
            clientId: String = "https://wallet.a-sit.at/",
            remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
            requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { jws, authnRequest -> true },
            scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever = { null },
        ): OidcSiopWallet {
            return OidcSiopWallet(
                holder = holder,
                agentPublicKey = keyPairAdapter.publicKey,
                jwsService = jwsService,
                clock = clock,
                clientId = clientId,
                remoteResourceRetriever = remoteResourceRetriever,
                requestObjectJwsVerifier = requestObjectJwsVerifier,
                scopePresentationDefinitionRetriever = scopePresentationDefinitionRetriever,
            )
        }
    }

    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = clientId,
            authorizationEndpointUrl = clientId,
            responseTypesSupported = setOf(ID_TOKEN),
            scopesSupported = setOf(SCOPE_OPENID),
            subjectTypesSupported = setOf("pairwise", "public"),
            idTokenSigningAlgorithmsSupported = setOf(jwsService.algorithm),
            requestObjectSigningAlgorithmsSupported = setOf(jwsService.algorithm),
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
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
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<AuthenticationRequestParametersFrom> =
        AuthenticationRequestParser.createWithDefaults(
            remoteResourceRetriever = remoteResourceRetriever,
            requestObjectJwsVerifier = requestObjectJwsVerifier,
        ).parseAuthenticationRequestParameters(input)

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     */
    suspend fun createAuthnResponse(
        request: AuthenticationRequestParametersFrom,
    ): KmmResult<AuthenticationResponseResult> = createAuthnResponseParams(request).map {
        AuthenticationResponseFactory(jwsService).createAuthenticationResponse(
            request,
            response = it,
        )
    }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: AuthenticationRequestParametersFrom
    ): KmmResult<AuthenticationResponse> = startAuthorizationResponsePreparation(params).map {
        finalizeAuthorizationResponseParameters(
            params = params,
            preparationState = it,
        ).getOrThrow()
    }

    /**
     * Starts the authorization response building process from the RP's [params]
     */
    suspend fun startAuthorizationResponsePreparation(
        input: String,
    ): KmmResult<AuthorizationResponsePreparationState> =
        parseAuthenticationRequestParameters(input).map {
            startAuthorizationResponsePreparation(it).getOrThrow()
        }

    /**
     * Starts the authorization response building process from the RP's [params]
     */
    suspend fun startAuthorizationResponsePreparation(
        params: AuthenticationRequestParametersFrom
    ): KmmResult<AuthorizationResponsePreparationState> = catching {
        val clientMetadata = catching { params.parameters.loadClientMetadata() }.getOrNull()
        val presentationDefinition = params.parameters.loadPresentationDefinition()

        AuthorizationRequestValidator(remoteResourceRetriever).validateAuthorizationRequest(params)

        AuthorizationResponsePreparationState(
            clientMetadata = clientMetadata,
            presentationDefinition = presentationDefinition,
        )
    }

    /**
     * Finalize the authorization response
     *
     * @param request: the RP's [params]
     * @param preparationState: The preparation state from [startAuthorizationResponsePreparation]
     * @param inputDescriptorSubmissions: Map from input descriptor ids to [CredentialSubmission]
     */
    suspend fun finalizeAuthorizationResponse(
        request: AuthenticationRequestParametersFrom,
        preparationState: AuthorizationResponsePreparationState,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponseResult> = finalizeAuthorizationResponseParameters(
        params = request,
        preparationState = preparationState,
        inputDescriptorSubmissions = inputDescriptorSubmissions,
    ).map { responseParameters ->
        AuthenticationResponseFactory(jwsService).createAuthenticationResponse(
            request,
            responseParameters,
        )
    }


    /**
     * Finalize the authorization response parameters
     *
     * @param request: the RP's [params]
     * @param preparationState: The preparation state from [startAuthorizationResponsePreparation]
     * @param inputDescriptorSubmissions: Map from input descriptor ids to [CredentialSubmission]
     */
    suspend fun finalizeAuthorizationResponseParameters(
        params: AuthenticationRequestParametersFrom,
        preparationState: AuthorizationResponsePreparationState,
        inputDescriptorSubmissions: Map<String, CredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponse> = preparationState.catching {
        val certKey =
            (params as? AuthenticationRequestParametersFrom.JwsSigned)?.jwsSigned?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val clientJsonWebKeySet = clientMetadata?.loadJsonWebKeySet()

        val audience = params.extractAudience(clientJsonWebKeySet)

        val presentationFactory = PresentationFactory(jwsService)

        val idToken = presentationFactory.createSignedIdToken(
            clock = clock,
            agentPublicKey = agentPublicKey,
            request = params,
        ).getOrNull()?.serialize()

        val resultContainer = presentationDefinition?.let {
            presentationFactory.createPresentationExchangePresentation(
                holder = holder,
                params,
                audience,
                presentationDefinition,
                clientMetadata,
                inputDescriptorSubmissions
            ).getOrThrow()
        }
        val vpToken =
            resultContainer?.presentationResults?.map { it.toJsonPrimitive() }?.singleOrArray()
        val presentationSubmission = resultContainer?.presentationSubmission

        val parameters = AuthenticationResponseParameters(
            state = params.parameters.state,
            idToken = idToken,
            vpToken = vpToken,
            presentationSubmission = presentationSubmission,
        )

        val jsonWebKeys = clientJsonWebKeySet?.keys?.combine(certKey)
        AuthenticationResponse(parameters, clientMetadata, jsonWebKeys)
    }

    private fun AuthenticationRequestParametersFrom.extractAudience(
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
        ?: throw OAuth2Exception(Errors.INVALID_REQUEST).also { Napier.w("client metadata is not specified in $this") }

    private fun Holder.CreatePresentationResult.toJsonPrimitive() = when (this) {
        is Holder.CreatePresentationResult.Signed -> {
            // must be a string
            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.5-1
            JsonPrimitive(jws)
        }

        is Holder.CreatePresentationResult.SdJwt -> {
            // must be a string
            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3.5-1
            JsonPrimitive(sdJwt)
        }

        is Holder.CreatePresentationResult.Document -> {
            // must be a string
            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.5-1
            JsonPrimitive(
                document.serialize().encodeToString(Base16(strict = true))
            )
        }
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
    operator fun invoke(jws: JwsSigned, authnRequest: AuthenticationRequestParameters): Boolean
}

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> {
    return certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
}
