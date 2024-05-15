package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionBuilder
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST_JWT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.QUERY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
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
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction? = null,
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdSchemes.PRE_REGISTERED]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier? = null,
    /**
     * Need to implement if the presentation definition needs to be derived from a scope value.
     * See [ScopePresentationDefinitionRetriever] for implementation instructions.
     */
    private val scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = null,
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
            clock: Clock = Clock.System,
            clientId: String = "https://wallet.a-sit.at/",
            remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
            requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { jws, authnRequest -> true },
            scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = { null },
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            clock = clock,
            clientId = clientId,
            remoteResourceRetriever = remoteResourceRetriever,
            requestObjectJwsVerifier = requestObjectJwsVerifier,
            scopePresentationDefinitionRetriever = scopePresentationDefinitionRetriever,
        )
    }

    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = clientId,
            authorizationEndpointUrl = clientId,
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
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<AuthenticationRequestParameters> {
        val parsedParams = kotlin.run { // maybe it is a request JWS
            parseRequestObjectJws(input)
        } ?: kotlin.runCatching { // maybe it's in the URL parameters
            Url(input).parameters.flattenEntries().toMap()
                .decodeFromUrlQuery<AuthenticationRequestParameters>()
        }.getOrNull() ?: kotlin.runCatching {  // maybe it is already a JSON string
            AuthenticationRequestParameters.deserialize(input).getOrNull()
        }.getOrNull() ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
            Napier.w("Could not parse authentication request: $input")
        })

        val extractedParams = parsedParams.let { extractRequestObject(it) ?: it }
        if (parsedParams.clientId != null && extractedParams.clientId != parsedParams.clientId) {
            return KmmResult.failure<AuthenticationRequestParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("ClientIds changed: ${parsedParams.clientId} to ${extractedParams.clientId}") }
        }
        return KmmResult.success(extractedParams)
    }

    private suspend fun extractRequestObject(params: AuthenticationRequestParameters): AuthenticationRequestParameters? =
        params.request?.let { requestObject ->
            parseRequestObjectJws(requestObject)
        } ?: params.requestUri?.let { uri ->
            remoteResourceRetriever?.invoke(uri)
                ?.let { parseAuthenticationRequestParameters(it).getOrNull() }
        }

    private fun parseRequestObjectJws(requestObject: String): AuthenticationRequestParameters? {
        return JwsSigned.parse(requestObject)?.let { jws ->
            val params = AuthenticationRequestParameters.deserialize(jws.payload.decodeToString())
                .getOrElse { ex ->
                    Napier.w("parseRequestObjectJws: Deserialization failed", ex)
                    return null
                }
            if (requestObjectJwsVerifier?.invoke(jws, params) != false) {
                params
            } else null.also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseBuilder] for preparing a response.
     */
    suspend fun startAuthenticationResponsePreparation(
        input: String,
    ): KmmResult<AuthenticationResponseBuilder> = startAuthenticationResponsePreparation(
        parameters = parseAuthenticationRequestParameters(input).getOrElse {
            return KmmResult.failure<AuthenticationResponseBuilder>(it)
                .also { Napier.w("Could not parse authentication request: $input") }
        },
    )

    suspend fun startAuthenticationResponsePreparation(
        parameters: AuthenticationRequestParameters,
    ): KmmResult<AuthenticationResponseBuilder> {
        val nonce = parameters.nonce ?: run {
            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("nonce is null") }
        }

        val responseType = parameters.responseType ?: run {
            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("response_type is not specified") }
        }

        if (!responseType.contains(ID_TOKEN) && !responseType.contains(VP_TOKEN)) {
            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("response_type is not supported") }
        }
        if (parameters.redirectUrl != null) {
            if (parameters.clientId != parameters.redirectUrl) {
                return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                    .also { Napier.w("client_id does not match redirect_uri") }
            }
        }

        val targetUrl = when (parameters.responseMode) {
            DIRECT_POST -> parameters.responseUrl ?: parameters.redirectUrl
            DIRECT_POST_JWT -> parameters.responseUrl ?: parameters.redirectUrl
            QUERY -> parameters.redirectUrl

            // default for vp_token and id_token is fragment
            else -> parameters.redirectUrl
        } ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST).also {
            Napier.w("target url is not specified")
        })

        val clientMetadata = retrieveClientMetadata(parameters)
            ?: return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client metadata is not specified") }

        // TODO Check removed for EUDI interop
//        if (clientMetadata.subjectSyntaxTypesSupported == null || URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported) {
//            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
//                .also { Napier.w("Incompatible subject syntax types algorithms") }
//        }

        val audience = retrieveAudience(clientMetadata)
            ?: return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("Could not parse audience") }

        val presentationDefinition = retrievePresentationDefinition(parameters)
        if (!parameters.responseType.contains(VP_TOKEN) && presentationDefinition == null) {
            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("vp_token not requested") }
        }

        return KmmResult.success(
            AuthenticationResponseBuilder(
                parameters = parameters,
                responseType = responseType,
                targetUrl = targetUrl,
                clientMetadata = clientMetadata,
                audience = audience,
                nonce = nonce,
                submissionBuilder = presentationDefinition?.let {
                    PresentationSubmissionBuilder(
                        presentationDefinition = presentationDefinition,
                        fallbackFormatHolder = clientMetadata.vpFormats
                    ).also {
                        refreshPresentationSubmissionBuilder(it)
                    }
                },
            )
        )
    }

    suspend fun refreshPresentationSubmissionBuilder(presentationSubmissionBuilder: PresentationSubmissionBuilder) {
        presentationSubmissionBuilder.refreshInputDescriptors(
            holder = holder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    suspend fun finalizeAuthenticationResponseResult(
        authenticationResponseBuilder: AuthenticationResponseBuilder,
    ): KmmResult<AuthenticationResponseResult> {
        val responseParams = finalizeAuthenticationResponseParameters(
            authenticationResponseBuilder
        ).getOrElse {
            return KmmResult.failure(it)
        }

        return when (authenticationResponseBuilder.parameters.responseMode) {
            DIRECT_POST -> KmmResult.success(
                AuthenticationResponseResult.Post(
                    url = authenticationResponseBuilder.targetUrl,
                    params = responseParams.encodeToParameters(),
                )
            )

            DIRECT_POST_JWT -> {
                val responseParamsJws = jwsService.createSignedJwsAddingParams(
                    payload = responseParams.serialize().encodeToByteArray()
                ).getOrElse {
                    return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                }

                val jarm = AuthenticationResponseParameters(
                    response = responseParamsJws.serialize()
                )

                KmmResult.success(
                    AuthenticationResponseResult.Post(
                        url = authenticationResponseBuilder.targetUrl,
                        params = jarm.encodeToParameters(),
                    )
                )
            }

            QUERY -> {
                val url = URLBuilder(authenticationResponseBuilder.targetUrl).apply {
                    responseParams.encodeToParameters().forEach {
                        this.parameters.append(it.key, it.value)
                    }
                }.buildString()

                KmmResult.success(
                    AuthenticationResponseResult.Redirect(
                        url = url,
                        params = responseParams,
                    )
                )
            }

            else -> {
                // default for vp_token and id_token is fragment
                val url = URLBuilder(authenticationResponseBuilder.targetUrl).apply {
                    encodedFragment = responseParams.encodeToParameters().formUrlEncode()
                }.buildString()

                KmmResult.success(
                    AuthenticationResponseResult.Redirect(
                        url, responseParams
                    )
                )
            }
        }
    }

    suspend fun finalizeAuthenticationResponseParameters(
        authenticationResponseBuilder: AuthenticationResponseBuilder,
    ): KmmResult<AuthenticationResponseParameters> {
        val signedIdToken = if (!authenticationResponseBuilder.responseType.contains(ID_TOKEN)) {
            null
        } else {
            createIdToken(
                nonce = authenticationResponseBuilder.nonce,
                audience = authenticationResponseBuilder.parameters.redirectUrl
                    ?: authenticationResponseBuilder.parameters.clientId,
            ).getOrElse {
                Napier.w("Could not sign id_token", it)
                return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
            }
        }

        val presentationResultContainer = authenticationResponseBuilder.submissionBuilder?.let {
            if (!it.isValid()) {
                Napier.w("submission requirements are not satisfied")
                return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
            }
            holder.createPresentation(
                challenge = authenticationResponseBuilder.nonce,
                audienceId = authenticationResponseBuilder.audience,
                presentationDefinitionId = it.presentationDefinitionId,
                presentationSubmissionSelection = it.submissionSelection
            ).getOrElse { exception ->
                Napier.w("Could not create presentation: ${exception.message}")
                return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
            }
        }
        presentationResultContainer?.let {
            authenticationResponseBuilder.clientMetadata.vpFormats?.let { supportedFormats ->
                presentationResultContainer.presentationSubmission.descriptorMap?.mapIndexed { index, descriptor ->
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
                        return KmmResult.failure(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED).also {
                            Napier.w(
                                "Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats"
                            )
                        })
                    }
                }
            }
        }

        return KmmResult.success(
            AuthenticationResponseParameters(
                idToken = signedIdToken?.serialize(),
                state = authenticationResponseBuilder.parameters.state,
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

    private suspend fun retrieveClientMetadata(params: AuthenticationRequestParameters): RelyingPartyMetadata? {
        return params.clientMetadata ?: params.clientMetadataUri?.let { uri ->
            remoteResourceRetriever?.invoke(uri)
                ?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
        }
    }

    private suspend fun retrieveAudience(clientMetadata: RelyingPartyMetadata): String? {
        return clientMetadata.jsonWebKeySet?.keys?.firstOrNull()?.identifier
            ?: clientMetadata.jsonWebKeySetUrl?.let {
                remoteResourceRetriever?.invoke(it)
                    ?.let { JsonWebKeySet.deserialize(it) }?.keys?.firstOrNull()?.identifier
            }
    }

    private suspend fun retrievePresentationDefinition(params: AuthenticationRequestParameters): PresentationDefinition? {
        return params.presentationDefinition ?: params.presentationDefinitionUrl?.let {
            remoteResourceRetriever?.invoke(it)
        }?.let {
            PresentationDefinition.deserialize(it).getOrNull()
        } ?: params.scope?.split(" ")?.firstNotNullOfOrNull {
            scopePresentationDefinitionRetriever?.invoke(it)
        }
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