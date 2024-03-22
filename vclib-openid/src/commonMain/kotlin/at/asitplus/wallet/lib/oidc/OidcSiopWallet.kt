package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.QUERY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidvci.IssuerMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpHeaders
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.util.flattenEntries
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
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
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    private val clock: Clock = Clock.System,
    private val clientId: String = "https://wallet.a-sit.at/",
    /**
     * Need to implement if JSON web keys are not specified directly as `jwks` in authn requests,
     * but need to be retrieved from the `jwks_uri`. Implementations need to fetch the URL passed and return the
     * content parsed as [JsonWebKeySet].
     */
    private val jwkSetRetriever: (String) -> JsonWebKeySet? = { null },
    /**
     * Need to implement if the request parameters need to be fetched, i.e. the actual authn request can
     * be retrieved from that URL. Implementations need to fetch the url and return request object candidates that have been retrieved.
     */
    private val requestObjectCandidateRetriever: RequestObjectCandidateRetriever = { listOf() },
) {
    companion object {
        fun newInstance(
            holder: Holder,
            cryptoService: CryptoService,
            jwsService: JwsService = DefaultJwsService(cryptoService),
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
            clock: Clock = Clock.System,
            httpClient: HttpClient,
            clientId: String = "https://wallet.a-sit.at/",
            jwkSetRetriever: (String) -> JsonWebKeySet? = { null },
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            clock = clock,
            clientId = clientId,
            jwkSetRetriever = jwkSetRetriever,
            requestObjectCandidateRetriever = httpClient.asRequestObjectCandidateRetriever,
        )

        // mark this as internal so it can be used for testing purposes
        // the request object candidate retriever should usually be derived from a http client as in the other constructor
        internal fun newInstance(
            holder: Holder,
            cryptoService: CryptoService,
            jwsService: JwsService = DefaultJwsService(cryptoService),
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
            clock: Clock = Clock.System,
            clientId: String = "https://wallet.a-sit.at/",
            jwkSetRetriever: (String) -> JsonWebKeySet? = { null },
            requestObjectCandidateRetriever: RequestObjectCandidateRetriever = { listOf() },
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            clock = clock,
            clientId = clientId,
            jwkSetRetriever = jwkSetRetriever,
            requestObjectCandidateRetriever = requestObjectCandidateRetriever,
        )
    }

    /**
     * Possible outcomes of creating the OIDC Authentication Response
     */
    sealed class AuthenticationResponseResult {
        /**
         * Wallet returns the [AuthenticationResponseParameters] as form encoded parameters, which shall be posted to
         * `redirect_uri` of the Relying Party, i.e. clients should execute that POST to call the RP again.
         */
        data class Post(val url: String, val content: String) : AuthenticationResponseResult()

        /**
         * Wallet returns the [AuthenticationResponseParameters] as fragment parameters appended to the
         * `redirect_uri` of the Relying Party, i.e. clients should simply open the URL to call the RP again.
         */
        data class Redirect(val url: String) : AuthenticationResponseResult()
    }

    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = clientId,
            authorizationEndpointUrl = clientId,
            responseTypesSupported = arrayOf(ID_TOKEN),
            scopesSupported = arrayOf(SCOPE_OPENID),
            subjectTypesSupported = arrayOf("pairwise", "public"),
            idTokenSigningAlgorithmsSupported = arrayOf(jwsService.algorithm.identifier),
            requestObjectSigningAlgorithmsSupported = arrayOf(jwsService.algorithm.identifier),
            subjectSyntaxTypesSupported = arrayOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
            idTokenTypesSupported = arrayOf(IdTokenType.SUBJECT_SIGNED),
            presentationDefinitionUriSupported = false,
        )
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseResult] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun createAuthnResponse(input: String): KmmResult<AuthenticationResponseResult> {
        val params = retrieveAuthenticationRequestParameters(input)
        return createAuthnResponse(params)
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun retrieveAuthenticationRequestParameters(input: String): AuthenticationRequestParameters {
        val params = kotlin.run {
            // maybe it's already a request jws?
            parseRequestObjectJws(input)
        } ?: kotlin.runCatching {
            // maybe it's a url that already encodes the authentication request as url parameters
            Url(input).parameters.flattenEntries().toMap()
                .decodeFromUrlQuery<AuthenticationRequestParameters>()
        }.getOrNull() ?: kotlin.runCatching {
            // maybe it's a url that yields the request object in some other way
            // currently supported in order of priority:
            // 1. use redirect location as new starting point if available
            // 2. use resonse body as new starting point
            // - maybe it's just a jws that needs to be parsed, but let's also support a url there
            val url = Url(input)
            val candidates = requestObjectCandidateRetriever.invoke(url)
            var result: AuthenticationRequestParameters? = null
            for (candidate in candidates) {
                result = kotlin.runCatching {
                    retrieveAuthenticationRequestParameters(candidate)
                }.getOrDefault(result)
                if (result != null) break
            }
            result
        }.getOrNull() ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("Could not parse authentication request: $input") }

        val requestParams = params.requestUri?.let {
            // go down the rabbit hole following the request_uri parameters
            retrieveAuthenticationRequestParameters(it).also { newParams ->
                if (params.clientId != newParams.clientId) {
                    throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.e("Client ids do not match: before: $params, after: $newParams") }
                }
            }
        } ?: params

        val authenticationRequestParameters = requestParams.let { extractRequestObject(it) ?: it }
        if (authenticationRequestParameters.clientId != requestParams.clientId) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("Client ids do not match: outer: $requestParams, inner: $authenticationRequestParameters") }
        }
        return authenticationRequestParameters
    }

    private fun extractRequestObject(params: AuthenticationRequestParameters): AuthenticationRequestParameters? {
        params.request?.let { requestObject ->
            return parseRequestObjectJws(requestObject)
        }
        return null
    }

    private fun parseRequestObjectJws(requestObject: String): AuthenticationRequestParameters? {
        JwsSigned.parse(requestObject)?.let { jws ->
            if (verifierJwsService.verifyJwsObject(jws)) {
                return kotlin.runCatching {
                    AuthenticationRequestParameters.deserialize(jws.payload.decodeToString())
                }.getOrNull()
            }
        }
        return null
    }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     */
    suspend fun createAuthnResponse(
        request: AuthenticationRequestParameters
    ): KmmResult<AuthenticationResponseResult> = createAuthnResponseParams(request).fold(
        onSuccess = { responseParams ->
            if (request.responseType == null) {
                return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
            }
            if (!request.responseType.contains(ID_TOKEN) && !request.responseType.contains(VP_TOKEN)) {
                return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
            }
            if (request.responseMode?.startsWith(POST) == true) {
                if (request.redirectUrl == null)
                    return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                val body = responseParams.encodeToParameters().formUrlEncode()
                return KmmResult.success(
                    AuthenticationResponseResult.Post(
                        request.redirectUrl,
                        body
                    )
                )
            } else if (request.responseMode?.startsWith(DIRECT_POST) == true) {
                if (request.responseUrl == null || request.redirectUrl != null)
                    return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                val body = responseParams.encodeToParameters().formUrlEncode()
                return KmmResult.success(
                    AuthenticationResponseResult.Post(
                        request.responseUrl,
                        body
                    )
                )
            } else if (request.responseMode?.startsWith(QUERY) == true) {
                if (request.redirectUrl == null)
                    return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                val url = URLBuilder(request.redirectUrl)
                    .apply {
                        responseParams.encodeToParameters().forEach {
                            this.parameters.append(it.key, it.value)
                        }
                    }
                    .buildString()
                return KmmResult.success(AuthenticationResponseResult.Redirect(url))
            } else {
                // default for vp_token and id_token is fragment
                if (request.redirectUrl == null)
                    return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                val url = URLBuilder(request.redirectUrl)
                    .apply { encodedFragment = responseParams.encodeToParameters().formUrlEncode() }
                    .buildString()
                return KmmResult.success(AuthenticationResponseResult.Redirect(url))
            }
        },
        onFailure = {
            return KmmResult.failure(it)
        }
    )

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: AuthenticationRequestParameters
    ): KmmResult<AuthenticationResponseParameters> {
        if (params.clientMetadata == null) {
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client metadata is not specified") }
        }
        val audience = params.clientMetadata.jsonWebKeySet?.keys?.firstOrNull()?.identifier
            ?: params.clientMetadata.jsonWebKeySetUrl?.let { jwkSetRetriever.invoke(it)?.keys?.firstOrNull()?.identifier }
            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("Could not parse audience") }
        if (URN_TYPE_JWK_THUMBPRINT !in params.clientMetadata.subjectSyntaxTypesSupported)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
                .also { Napier.w("Incompatible subject syntax types algorithms") }
        if (params.clientIdScheme == OpenIdConstants.ClientIdSchemes.REDIRECT_URI && params.redirectUrl == null) {
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client_id_scheme is redirect_uri, but that is not set") }
        }
        if (params.redirectUrl != null) {
            if (params.clientId != params.redirectUrl)
                return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                    .also { Napier.w("client_id does not match redirect_uri") }
        }
        if (params.responseType == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("response_type is not specified") }
        if (!params.responseType.contains(VP_TOKEN) && params.presentationDefinition == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("vp_token not requested") }
        if (params.clientMetadata.vpFormats != null) {
            if (params.clientMetadata.vpFormats.jwtVp?.algorithms?.contains(jwsService.algorithm.identifier) != true)
                return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                    .also { Napier.w("Incompatible JWT algorithms") }
            if (params.clientMetadata.vpFormats.jwtSd?.algorithms?.contains(jwsService.algorithm.identifier) != true)
                return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                    .also { Napier.w("Incompatible JWT algorithms") }
            if (params.clientMetadata.vpFormats.msoMdoc?.algorithms?.contains(jwsService.algorithm.identifier) != true)
                return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                    .also { Napier.w("Incompatible JWT algorithms") }
        }
        if (params.nonce == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("nonce is null") }

        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val idToken = IdToken(
            issuer = agentJsonWebKey.jwkThumbprint,
            subject = agentJsonWebKey.jwkThumbprint,
            subjectJwk = agentJsonWebKey,
            audience = params.redirectUrl ?: params.clientId,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = params.nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        val signedIdToken = jwsService.createSignedJwsAddingParams(payload = jwsPayload).getOrElse {
            Napier.w("Could not sign id_token", it)
            return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
        }

        val requestedAttributeTypes = (params.scope ?: "").split(" ")
            .filterNot { it == SCOPE_OPENID }.filterNot { it == SCOPE_PROFILE }
            .filter { it.isNotEmpty() }
        val requestedNamespace = params.presentationDefinition?.inputDescriptors
            ?.mapNotNull { it.constraints }
            ?.flatMap { it.fields?.toList() ?: listOf() }
            ?.firstOrNull { it.path.toList().contains("$.mdoc.namespace") }
            ?.filter?.const
        val requestedSchemes = mutableListOf<ConstantIndex.CredentialScheme>()
        if (requestedNamespace != null) {
            requestedSchemes.add(AttributeIndex.resolveIsoNamespace(requestedNamespace)
                ?: return KmmResult.failure<AuthenticationResponseParameters>(
                    OAuth2Exception(
                        Errors.USER_CANCELLED
                    )
                )
                    .also { Napier.w("Could not resolve requested namespace $requestedNamespace") })
            requestedAttributeTypes.forEach { requestedAttributeTyp ->
                requestedSchemes.add(AttributeIndex.resolveAttributeType(requestedAttributeTyp)
                    ?: return KmmResult.failure<AuthenticationResponseParameters>(
                        OAuth2Exception(Errors.USER_CANCELLED)
                    )
                        .also { Napier.w("Could not resolve requested attribute type $it") })
            }
        }
        val requestedClaims = params.presentationDefinition?.inputDescriptors
            ?.mapNotNull { it.constraints }
            ?.flatMap { it.fields?.toList() ?: listOf() }
            ?.flatMap { it.path.toList() }
            ?.filter { it != "$.type" }
            ?.filter { it != "$.mdoc.doctype" }
            ?.map { it.removePrefix("\$.mdoc.") }
            ?.map { it.removePrefix("\$.") }
            ?: listOf()
        val vp = holder.createPresentation(
            challenge = params.nonce,
            audienceId = audience,
            credentialSchemes = requestedSchemes.toList().ifEmpty { null },
            requestedClaims = requestedClaims.ifEmpty { null }
        )
            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.USER_CANCELLED))
                .also { Napier.w("Could not create presentation") }

        when (vp) {
            is Holder.CreatePresentationResult.Signed -> {
                val presentationSubmission = PresentationSubmission(
                    id = uuid4().toString(),
                    definitionId = params.presentationDefinition?.id ?: uuid4().toString(),
                    descriptorMap = params.presentationDefinition?.inputDescriptors?.map {
                        PresentationSubmissionDescriptor(
                            id = it.id,
                            format = ClaimFormatEnum.JWT_VP,
                            path = "\$",
                            nestedPath = PresentationSubmissionDescriptor(
                                id = uuid4().toString(),
                                format = ClaimFormatEnum.JWT_VC,
                                path = "\$.verifiableCredential[0]"
                            ),
                        )
                    }
                )
                return KmmResult.success(
                    AuthenticationResponseParameters(
                        idToken = signedIdToken.serialize(),
                        state = params.state,
                        vpToken = vp.jws,
                        presentationSubmission = presentationSubmission,
                    )
                )
            }

            is Holder.CreatePresentationResult.SdJwt -> {
                val presentationSubmission = PresentationSubmission(
                    id = uuid4().toString(),
                    definitionId = params.presentationDefinition?.id ?: uuid4().toString(),
                    descriptorMap = params.presentationDefinition?.inputDescriptors?.map {
                        PresentationSubmissionDescriptor(
                            id = it.id,
                            format = ClaimFormatEnum.JWT_SD,
                            path = "\$",
                        )
                    }
                )
                return KmmResult.success(
                    AuthenticationResponseParameters(
                        idToken = signedIdToken.serialize(),
                        state = params.state,
                        vpToken = vp.sdJwt,
                        presentationSubmission = presentationSubmission,
                    )
                )
            }

            is Holder.CreatePresentationResult.Document -> {
                val presentationSubmission = PresentationSubmission(
                    id = uuid4().toString(),
                    definitionId = params.presentationDefinition?.id ?: uuid4().toString(),
                    descriptorMap = params.presentationDefinition?.inputDescriptors?.map {
                        PresentationSubmissionDescriptor(
                            id = it.id,
                            format = ClaimFormatEnum.MSO_MDOC,
                            path = "\$",
                        )
                    }
                )
                return KmmResult.success(
                    AuthenticationResponseParameters(
                        idToken = signedIdToken.serialize(),
                        state = params.state,
                        vpToken = vp.document.serialize().encodeToString(Base16(strict = true)),
                        presentationSubmission = presentationSubmission,
                    )
                )
            }

        }
    }

}

typealias RequestObjectCandidateRetriever = suspend (Url) -> List<String>

private val HttpClient.asRequestObjectCandidateRetriever: RequestObjectCandidateRetriever
    get() = {
        val response = this.get(it)
        listOfNotNull(
            response.headers[HttpHeaders.Location],
            response.bodyAsText(),
        )
    }