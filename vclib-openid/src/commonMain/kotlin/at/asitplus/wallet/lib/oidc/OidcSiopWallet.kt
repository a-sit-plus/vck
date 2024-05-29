package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InputDescriptorCredentialSubmission
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import at.asitplus.wallet.lib.agent.toDefaultSubmission
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationPreparationState
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidc.helpers.AuthenticationResponsePreparationState
import at.asitplus.wallet.lib.oidc.helpers.ClientIdSchemeParameters
import at.asitplus.wallet.lib.oidc.helpers.ClientIdSchemeParametersFactory
import at.asitplus.wallet.lib.oidc.helpers.ResponseModeParameters
import at.asitplus.wallet.lib.oidc.helpers.ResponseModeParametersFactory
import at.asitplus.wallet.lib.oidvci.IssuerMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.util.flattenEntries
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlin.time.Duration.Companion.seconds


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * The [holder] creates the Authentication Response, see [OidcSiopVerifier] for the verifier.
 */
class OidcSiopWallet private constructor(
    private val holder: Holder,
    private val agentPublicKey: CryptoPublicKey,
    private val jwsService: JwsService,
    private val clock: Clock,
    private val clientId: String,
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
    /**
     * Need to implement in order to enforce authorization rules on
     * credential attributes that are to be disclosed.
     */
    private val pathAuthorizationValidator: PathAuthorizationValidator? = null,
) {
    companion object {
        fun newDefaultInstance(
            cryptoService: CryptoService = DefaultCryptoService(),
            holder: Holder = HolderAgent.newDefaultInstance(cryptoService),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            clock: Clock? = null,
            clientId: String? = null,
            remoteResourceRetriever: RemoteResourceRetrieverFunction? = null,
            requestObjectJwsVerifier: RequestObjectJwsVerifier? = null,
            scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = null,
            pathAuthorizationValidator: PathAuthorizationValidator? = null,
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            clock = clock ?: Clock.System,
            clientId = clientId ?: "https://wallet.a-sit.at/",
            remoteResourceRetriever = remoteResourceRetriever ?: { null },
            requestObjectJwsVerifier = requestObjectJwsVerifier ?: { _, _ -> true },
            scopePresentationDefinitionRetriever = scopePresentationDefinitionRetriever ?: { null },
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = this.clientId,
            authorizationEndpointUrl = this.clientId,
            responseTypesSupported = setOf(ID_TOKEN),
            scopesSupported = setOf(SCOPE_OPENID),
            subjectTypesSupported = setOf("pairwise", "public"),
            idTokenSigningAlgorithmsSupported = setOf(jwsService.algorithm.identifier),
            requestObjectSigningAlgorithmsSupported = setOf(jwsService.algorithm.identifier),
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
            idTokenTypesSupported = setOf(IdTokenType.SUBJECT_SIGNED),
            presentationDefinitionUriSupported = false,
        )
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<AuthenticationRequestParametersFrom<*>> {
        val parsedParams = kotlin.run { // maybe it is a request JWS
            parseRequestObjectJws(input)
        } ?: kotlin.runCatching { // maybe it's in the URL parameters
            Url(input).let {
                AuthenticationRequestParametersFrom.Uri(
                    it,
                    it.parameters.flattenEntries().toMap()
                        .decodeFromUrlQuery<AuthenticationRequestParameters>()
                )
            }
        }.onFailure { it.printStackTrace() }.getOrNull()
        ?: kotlin.runCatching {  // maybe it is already a JSON string
            AuthenticationRequestParametersFrom.Json(
                input, AuthenticationRequestParameters.deserialize(input).getOrThrow()
            )
        }.getOrNull() ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
            Napier.w("Could not parse authentication request: $input")
        })

        val extractedParams = parsedParams.let { extractRequestObject(it.parameters) ?: it }
        if (parsedParams.parameters.clientId != null && extractedParams.parameters.clientId != parsedParams.parameters.clientId) {
            return KmmResult.failure<AuthenticationRequestParametersFrom<*>>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("ClientIds changed: ${parsedParams.parameters.clientId} to ${extractedParams.parameters.clientId}") }
        }
        return KmmResult.success(extractedParams)
    }

    private suspend fun extractRequestObject(params: AuthenticationRequestParameters): AuthenticationRequestParametersFrom<*>? =
        params.request?.let { requestObject ->
            parseRequestObjectJws(requestObject)
        } ?: params.requestUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { parseAuthenticationRequestParameters(it).getOrNull() }
        }

    private fun parseRequestObjectJws(requestObject: String): AuthenticationRequestParametersFrom.JwsSigned? {
        return JwsSigned.parse(requestObject).getOrNull()?.let { jws ->
            val params = AuthenticationRequestParameters.deserialize(jws.payload.decodeToString())
                .getOrElse {
                    Napier.w("parseRequestObjectJws: Deserialization failed", it)
                    return null
                }
            if (requestObjectJwsVerifier.invoke(jws, params)) {
                AuthenticationRequestParametersFrom.JwsSigned(
                    jwsSigned = jws, parameters = params
                )
            } else null.also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponsePreparationState] for preparing a response.
     */
    suspend fun startAuthenticationResponsePreparation(
        input: String,
    ): KmmResult<AuthenticationResponsePreparationState> = startAuthenticationResponsePreparation(
        request = parseAuthenticationRequestParameters(input).getOrElse {
            Napier.w("Could not parse authentication request: $input")
            return KmmResult.failure(it)
        },
    )

    suspend fun startAuthenticationResponsePreparation(
        request: AuthenticationRequestParametersFrom<*>,
    ): KmmResult<AuthenticationResponsePreparationState> {
        val nonce = request.parameters.nonce ?: run {
            Napier.w("nonce is null")
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
        }

        val responseType = request.parameters.responseType ?: run {
            Napier.w("response_type is not specified")
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
        }

        if (!responseType.contains(ID_TOKEN) && !responseType.contains(VP_TOKEN)) {
            Napier.w("response_type is not supported")
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
        }

        val responseModeParameters: ResponseModeParameters =
            ResponseModeParametersFactory(request.parameters).createResponseModeParameters()
                .getOrElse {
                    return KmmResult.failure(it)
                }

        val clientIdScheme = request.parameters.clientIdScheme
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.REDIRECT_URI) {
            if (request.parameters.clientMetadata == null && request.parameters.clientMetadataUri == null) {
                Napier.w("client_id_scheme is redirect_uri, but metadata is not set")
                return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
            }
        }

        val clientIdSchemeParameters =
            ClientIdSchemeParametersFactory(request).createClientIdSchemeParameters().getOrElse {
                return KmmResult.failure(it)
            }

        // TODO Check removed for EUDI interop
//        if (clientMetadata.subjectSyntaxTypesSupported == null || URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported) {
//            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
//                .also { Napier.w("Incompatible subject syntax types algorithms") }
//        }

        val clientMetadata = retrieveClientMetadata(request.parameters) ?: run {
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
                Napier.w("client metadata is not specified")
            })
        }

        val audience = retrieveAudience(clientMetadata) ?: clientIdSchemeParameters?.let {
            if (it is ClientIdSchemeParameters.X509ClientIdSchemeParameters) {
                request.parameters.clientId
            } else null
        } ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
            Napier.w("Could not parse audience")
        })


        val presentationDefinition = retrievePresentationDefinition(request.parameters)
        if (!request.parameters.responseType.contains(VP_TOKEN) && presentationDefinition == null) {
            return KmmResult.failure<AuthenticationResponsePreparationState>(
                OAuth2Exception(
                    Errors.INVALID_REQUEST
                )
            ).also { Napier.w("vp_token not requested") }
        }

        return KmmResult.success(
            AuthenticationResponsePreparationState(
                parameters = request.parameters,
                responseType = responseType,
                responseModeParameters = responseModeParameters,
                clientIdSchemeParameters = clientIdSchemeParameters,
                clientMetadata = clientMetadata,
                audience = audience,
                nonce = nonce,
                presentationPreparationState = presentationDefinition?.let {
                    try {
                        PresentationPreparationState(
                            presentationDefinition = presentationDefinition,
                            fallbackFormatHolder = clientMetadata.vpFormats
                        ).also {
                            refreshPresentationPreparationState(it)
                        }
                    } catch (e: Throwable) {
                        return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
                            e.message?.let { Napier.w(it) }
                        })
                    }
                },
            )
        )
    }

    /**
     * Users of the library need to call this method in case the stored credentials change.
     */
    @Suppress("MemberVisibilityCanBePrivate")
    suspend fun refreshPresentationPreparationState(presentationPreparationState: PresentationPreparationState) {
        presentationPreparationState.refreshInputDescriptorMatches(
            holder = holder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    suspend fun finalizeAuthenticationResponseResult(
        authenticationResponsePreparationState: AuthenticationResponsePreparationState,
        inputDescriptorCredentialSubmissions: Map<String, InputDescriptorCredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponseResult> {
        val responseParams = finalizeAuthenticationResponseParameters(
            authenticationResponsePreparationState,
            inputDescriptorCredentialSubmissions = inputDescriptorCredentialSubmissions,
        ).getOrElse {
            return KmmResult.failure(it)
        }

        return AuthenticationResponseResultFactory(
            responseParameters = responseParams,
            responseModeParameters = authenticationResponsePreparationState.responseModeParameters
        ).createAuthenticationResponseResult()
    }

    inner class AuthenticationResponseResultFactory(
        val responseModeParameters: ResponseModeParameters,
        val responseParameters: AuthenticationResponseParameters,
    ) {
        suspend fun createAuthenticationResponseResult(): KmmResult<AuthenticationResponseResult> {
            return when (responseModeParameters) {
                is ResponseModeParameters.DirectPost -> KmmResult.success(
                    AuthenticationResponseResult.Post(
                        url = responseModeParameters.responseUrl,
                        params = responseParameters.encodeToParameters(),
                    )
                )

                is ResponseModeParameters.DirectPostJwt -> KmmResult.runCatching {
                    authnResponseDirectPostJwt(
                        responseUrl = responseModeParameters.responseUrl,
                        responseParams = responseParameters,
                    )
                }.wrap()

                is ResponseModeParameters.Query -> KmmResult.runCatching {
                    authnResponseQuery(
                        redirectUrl = responseModeParameters.redirectUrl,
                        responseParams = responseParameters,
                    )
                }.wrap()

                is ResponseModeParameters.Fragment -> KmmResult.runCatching {
                    authnResponseFragment(
                        redirectUrl = responseModeParameters.redirectUrl,
                        responseParams = responseParameters,
                    )
                }.wrap()
            }
        }

        private suspend fun authnResponseDirectPostJwt(
            responseUrl: String,
            responseParams: AuthenticationResponseParameters,
        ): AuthenticationResponseResult.Post {
            val responseParamsJws = jwsService.createSignedJwsAddingParams(
                payload = responseParams.serialize().encodeToByteArray(),
                addX5c = false,
            ).getOrElse {
                Napier.w("authnResponseDirectPostJwt error", it)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
            val jarm = AuthenticationResponseParameters(response = responseParamsJws.serialize())

            return AuthenticationResponseResult.Post(
                url = responseUrl,
                params = jarm.encodeToParameters(),
            )
        }

        private fun authnResponseQuery(
            redirectUrl: String,
            responseParams: AuthenticationResponseParameters,
        ): AuthenticationResponseResult.Redirect {
            val url = URLBuilder(redirectUrl).apply {
                responseParams.encodeToParameters().forEach {
                    this.parameters.append(it.key, it.value)
                }
            }.buildString()

            return AuthenticationResponseResult.Redirect(
                url = url,
                params = responseParams,
            )
        }

        /**
         * That's the default for `id_token` and `vp_token`
         */
        private fun authnResponseFragment(
            redirectUrl: String, responseParams: AuthenticationResponseParameters
        ): AuthenticationResponseResult.Redirect {
            val url = URLBuilder(redirectUrl).apply {
                encodedFragment = responseParams.encodeToParameters().formUrlEncode()
            }.buildString()
            return AuthenticationResponseResult.Redirect(url, responseParams)
        }
    }

    internal suspend fun finalizeAuthenticationResponseParameters(
        authenticationResponsePreparationState: AuthenticationResponsePreparationState,
        inputDescriptorCredentialSubmissions: Map<String, InputDescriptorCredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponseParameters> {
        val signedIdToken =
            if (!authenticationResponsePreparationState.responseType.contains(ID_TOKEN)) {
                null
            } else {
                createIdToken(
                    nonce = authenticationResponsePreparationState.nonce,
                    audience = authenticationResponsePreparationState.parameters.redirectUrl
                        ?: authenticationResponsePreparationState.parameters.clientId,
                ).getOrElse {
                    Napier.w("Could not sign id_token", it)
                    return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
                }
            }

        val presentationResultContainer: Holder.PresentationResponseParameters? =
            authenticationResponsePreparationState.presentationPreparationState?.let { preparationState ->
                val credentialSubmissions = inputDescriptorCredentialSubmissions
                    ?: preparationState.inputDescriptorMatches.toDefaultSubmission()

                if (!preparationState.presentationSubmissionValidator.isValidSubmission(credentialSubmissions.keys)) {
                    Napier.w("submission requirements are not satisfied")
                    return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
                }

                holder.createPresentation(
                    challenge = authenticationResponsePreparationState.nonce,
                    audienceId = authenticationResponsePreparationState.audience,
                    presentationDefinitionId = preparationState.presentationDefinitionId,
                    presentationSubmissionSelection = credentialSubmissions,
                ).getOrElse { exception ->
                    Napier.w("Could not create presentation: ${exception.message}")
                    return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
                }
            }
        presentationResultContainer?.let {
            authenticationResponsePreparationState.clientMetadata.vpFormats?.let { supportedFormats ->
                presentationResultContainer.presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
                    val isMissingFormatSupport = when (descriptor.format) {
                        ClaimFormatEnum.JWT_VP -> supportedFormats.jwtVp?.algorithms?.contains(
                            jwsService.algorithm.identifier
                        ) != true

                        ClaimFormatEnum.JWT_SD -> supportedFormats.jwtSd?.algorithms?.contains(
                            jwsService.algorithm.identifier
                        ) != true

                        ClaimFormatEnum.MSO_MDOC -> supportedFormats.msoMdoc?.algorithms?.contains(
                            jwsService.algorithm.identifier
                        ) != true

                        else -> true
                    }

                    if (isMissingFormatSupport) {
                        Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                        return KmmResult.failure(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                    }
                }
            }
        }

        return KmmResult.success(
            AuthenticationResponseParameters(
                idToken = signedIdToken?.serialize(),
                state = authenticationResponsePreparationState.parameters.state,
                vpToken = presentationResultContainer?.presentationResults?.map {
                    when (it) {
                        is Holder.CreatePresentationResult.Signed -> {
                            // must be a string
                            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.5-1
                            JsonPrimitive(it.jws)
                        }

                        is Holder.CreatePresentationResult.SdJwt -> {
                            // must be a string
                            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3.5-1
                            JsonPrimitive(it.sdJwt)
                        }

                        is Holder.CreatePresentationResult.Document -> {
                            // must be a string
                            // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.5-1
                            JsonPrimitive(
                                it.document.serialize().encodeToString(Base16(strict = true))
                            )
                        }
                    }
                }?.let {
                    if (it.size == 1) it[0]
                    else buildJsonArray {
                        for (value in it) {
                            add(value)
                        }
                    }
                },
                presentationSubmission = presentationResultContainer?.presentationSubmission,
            ),
        )
    }

    private suspend fun createIdToken(audience: String?, nonce: String): KmmResult<JwsSigned> {
        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val idToken = IdToken(
            issuer = agentJsonWebKey.jwkThumbprint,
            subject = agentJsonWebKey.jwkThumbprint,
            subjectJwk = agentJsonWebKey,
            audience = audience ?: agentJsonWebKey.jwkThumbprint,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        return jwsService.createSignedJwsAddingParams(payload = jwsPayload)
    }


    private suspend fun retrieveClientMetadata(params: AuthenticationRequestParameters): RelyingPartyMetadata? {
        return params.clientMetadata ?: params.clientMetadataUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
        }
    }

    private suspend fun retrieveAudience(
        clientMetadata: RelyingPartyMetadata,
    ): String? {
        return clientMetadata.jsonWebKeySet?.keys?.firstOrNull()?.identifier
            ?: clientMetadata.jsonWebKeySetUrl?.let { url ->
                remoteResourceRetriever.invoke(url)?.let {
                    JsonWebKeySet.deserialize(it).getOrNull()
                }?.keys?.firstOrNull()?.identifier
            }
    }

    private suspend fun retrievePresentationDefinition(params: AuthenticationRequestParameters): PresentationDefinition? {
        return params.presentationDefinition ?: params.presentationDefinitionUrl?.let {
            remoteResourceRetriever.invoke(it)
        }?.let {
            PresentationDefinition.deserialize(it).getOrNull()
        } ?: params.scope?.split(" ")?.firstNotNullOfOrNull {
            scopePresentationDefinitionRetriever.invoke(it)
        }
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
typealias RequestObjectJwsVerifier = (jws: JwsSigned, authnRequest: AuthenticationRequestParameters) -> Boolean
