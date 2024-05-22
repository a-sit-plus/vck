package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.DIRECT_POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.DIRECT_POST_JWT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.FRAGMENT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.OTHER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.QUERY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidvci.IssuerMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
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
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdScheme.PRE_REGISTERED]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _, _ -> true },
    /**
     * Need to implement if the presentation definition needs to be derived from a scope value.
     * See [ScopePresentationDefinitionRetriever] for implementation instructions.
     */
    private val scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = null,
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
     * to create [AuthenticationResponseResult] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun createAuthnResponse(input: String): KmmResult<AuthenticationResponseResult> {
        val parameters = parseAuthenticationRequestParameters(input).getOrElse {
            return KmmResult.failure<AuthenticationResponseResult>(it)
                .also { Napier.w("Could not parse authentication request: $input") }
        }
        return createAuthnResponse(parameters)
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
                    it.parameters.flattenEntries().toMap().decodeFromUrlQuery<AuthenticationRequestParameters>()
                )
            }
        }.onFailure { it.printStackTrace() }.getOrNull() ?: kotlin.runCatching {  // maybe it is already a JSON string
            AuthenticationRequestParametersFrom.Json(
                input,
                AuthenticationRequestParameters.deserialize(input).getOrThrow()
            )
        }.getOrNull()
        ?: return KmmResult.failure<AuthenticationRequestParametersFrom<*>>(OAuth2Exception(Errors.INVALID_REQUEST))
            .also { Napier.w("Could not parse authentication request: $input") }

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
            val params = AuthenticationRequestParameters.deserialize(jws.payload.decodeToString()).getOrElse {
                return null
                    .also { Napier.w("parseRequestObjectJws: Deserialization failed", it) }
            }
            if (requestObjectJwsVerifier.invoke(jws, params)) AuthenticationRequestParametersFrom.JwsSigned(
                jws,
                params
            ) else null
                .also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
    }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     */
    suspend fun createAuthnResponse(
        request: AuthenticationRequestParametersFrom<*>
    ): KmmResult<AuthenticationResponseResult> = createAuthnResponseParams(request).fold(
        onSuccess = { responseParams ->
            if (request.parameters.responseType == null) {
                return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
            }
            if (!request.parameters.responseType.contains(ID_TOKEN)
                && !request.parameters.responseType.contains(VP_TOKEN)
            ) {
                return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
            }
            return when (request.parameters.responseMode) {
                DIRECT_POST -> KmmResult.runCatching { authnResponseDirectPost(request, responseParams) }.wrap()
                DIRECT_POST_JWT -> KmmResult.runCatching { authnResponseDirectPostJwt(request, responseParams) }.wrap()
                QUERY -> KmmResult.runCatching { authnResponseQuery(request, responseParams) }.wrap()
                FRAGMENT, null -> KmmResult.runCatching { authnResponseFragment(request, responseParams) }.wrap()
                is OTHER -> TODO()
            }
        },
        onFailure = {
            KmmResult.failure(it)
        }
    )


    private fun authnResponseDirectPost(
        request: AuthenticationRequestParametersFrom<*>,
        responseParams: AuthenticationResponseParameters
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Post(url, responseParams.encodeToParameters())
    }

    private suspend fun authnResponseDirectPostJwt(
        request: AuthenticationRequestParametersFrom<*>,
        responseParams: AuthenticationResponseParameters
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        val responseParamsJws = jwsService.createSignedJwsAddingParams(
            payload = responseParams.serialize().encodeToByteArray(), addX5c = false
        ).getOrElse {
            Napier.w("authnResponseDirectPostJwt error", it)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        val jarm = AuthenticationResponseParameters(response = responseParamsJws.serialize())
        return AuthenticationResponseResult.Post(url, jarm.encodeToParameters())
    }

    private fun authnResponseQuery(
        request: AuthenticationRequestParametersFrom<*>,
        responseParams: AuthenticationResponseParameters
    ): AuthenticationResponseResult.Redirect {
        if (request.parameters.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        val url = URLBuilder(request.parameters.redirectUrl).apply {
            responseParams.encodeToParameters().forEach {
                this.parameters.append(it.key, it.value)
            }
        }.buildString()
        return AuthenticationResponseResult.Redirect(url, responseParams)
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    private fun authnResponseFragment(
        request: AuthenticationRequestParametersFrom<*>,
        responseParams: AuthenticationResponseParameters
    ): AuthenticationResponseResult.Redirect {
        if (request.parameters.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        val url = URLBuilder(request.parameters.redirectUrl)
            .apply { encodedFragment = responseParams.encodeToParameters().formUrlEncode() }
            .buildString()
        return AuthenticationResponseResult.Redirect(url, responseParams)
    }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: AuthenticationRequestParametersFrom<*>
    ): KmmResult<AuthenticationResponseParameters> {
        // params.clientIdScheme is assumed to be OpenIdConstants.ClientIdSchemes.REDIRECT_URI,
        // because we'll require clientMetadata to be present, below
        val clientIdScheme = params.parameters.clientIdScheme
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.REDIRECT_URI
            && (params.parameters.clientMetadata == null && params.parameters.clientMetadataUri == null)
        ) {
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client_id_scheme is redirect_uri, but metadata is not set") }
        }

        val responseModeIsDirectPost =
            (params.parameters.responseMode == DIRECT_POST) || (params.parameters.responseMode == DIRECT_POST_JWT)
        if (responseModeIsDirectPost) {
            runCatching { verifyResponseModeDirectPost(params) }.onFailure { return KmmResult.failure(it) }
        }

        var leaf: X509Certificate? = null
        val clientIdSchemeIsX509 = (clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_DNS)
                || (clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_URI)
        if (clientIdSchemeIsX509) {
            if (params.parameters.clientMetadata == null
                || params !is AuthenticationRequestParametersFrom.JwsSigned
                || params.source.header.certificateChain == null
                || params.source.header.certificateChain!!.isEmpty()
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client_id_scheme is $clientIdScheme, but metadata is not set and no x5c certificate chain is present in the original authn request") }
            else { //basic checks done
                leaf = params.source.header.certificateChain!!.leaf
                if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
                    return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                        .also { Napier.w("client_id_scheme is $clientIdScheme, but no extensions were found in the leaf certificate") }
                }
                if (clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) {
                    val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames
                        ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                            .also { Napier.w("client_id_scheme is $clientIdScheme, but no dnsNames were found in the leaf certificate") }

                    if (!dnsNames.contains(params.parameters.clientId))
                        return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                            .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any dnsName in the leaf certificate") }

                    if (!responseModeIsDirectPost) {
                        val parsedUrl = params.parameters.redirectUrl?.let { Url(it) }
                            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                                .also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
                        //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the certificate it may allow the client to freely choose the redirect_uri value
                        if (parsedUrl.host != params.parameters.clientId) return KmmResult.failure<AuthenticationResponseParameters>(
                            OAuth2Exception(Errors.INVALID_REQUEST)
                        ).also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
                    }
                } else {
                    val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris
                        ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                            .also { Napier.w("client_id_scheme is $clientIdScheme, but no URIs were found in the leaf certificate") }
                    if (!uris.contains(params.parameters.clientId))
                        return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                            .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any URIs in the leaf certificate") }

                    if (params.parameters.clientId != params.parameters.redirectUrl)
                        return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                            .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match redirect_uri") }
                }
            }
        }

        // params.clientIdScheme is assumed to be OpenIdConstants.ClientIdSchemes.REDIRECT_URI,
        // because we'll require clientMetadata to be present, below
        val clientMetadata = params.parameters.clientMetadata
            ?: params.parameters.clientMetadataUri?.let { uri ->
                remoteResourceRetriever.invoke(uri)?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
            } ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client metadata is not specified") }
        val audience = clientMetadata.jsonWebKeySet?.keys?.firstOrNull()?.identifier
            ?: clientMetadata.jsonWebKeySetUrl?.let {
                remoteResourceRetriever.invoke(it)
                    ?.let { JsonWebKeySet.deserialize(it).getOrNull() }?.keys?.firstOrNull()?.identifier
                    ?: leaf?.let { params.parameters.clientId } //TODO is this even correct ????
            }
            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("Could not parse audience") }
        // TODO Check removed for EUDI interop
//        if (clientMetadata.subjectSyntaxTypesSupported == null || URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported)
//            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
//                .also { Napier.w("Incompatible subject syntax types algorithms") }

        if (!clientIdSchemeIsX509)
            if (params.parameters.redirectUrl != null) {
                if (params.parameters.clientId != params.parameters.redirectUrl)
                    return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                        .also { Napier.w("client_id does not match redirect_uri") }
            }

        if (params.parameters.responseType == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("response_type is not specified") }
        if (!params.parameters.responseType.contains(VP_TOKEN) && params.parameters.presentationDefinition == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("vp_token not requested") }
        val presentationDefinition = params.parameters.presentationDefinition
            ?: params.parameters.presentationDefinitionUrl?.let {
                remoteResourceRetriever.invoke(it)
            }?.let { PresentationDefinition.deserialize(it).getOrNull() }
            ?: params.parameters.scope?.split(" ")?.firstNotNullOfOrNull {
                scopePresentationDefinitionRetriever?.invoke(it)
            }
        if (!params.parameters.responseType.contains(VP_TOKEN) && presentationDefinition == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("vp_token not requested") }
        if (clientMetadata.vpFormats != null) {
            if (clientMetadata.vpFormats.jwtVp?.algorithms != null
                && clientMetadata.vpFormats.jwtVp?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                .also { Napier.w("Incompatible JWT algorithms") }
            if (clientMetadata.vpFormats.jwtSd?.algorithms != null
                && clientMetadata.vpFormats.jwtSd?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                .also { Napier.w("Incompatible JWT algorithms") }
            if (clientMetadata.vpFormats.msoMdoc?.algorithms != null
                && clientMetadata.vpFormats.msoMdoc?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                .also { Napier.w("Incompatible JWT algorithms") }
        }
        if (params.parameters.nonce == null)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("nonce is null") }

        val now = clock.now()
        // we'll assume jwk-thumbprint
        val agentJsonWebKey = agentPublicKey.toJsonWebKey()
        val idToken = IdToken(
            issuer = agentJsonWebKey.jwkThumbprint,
            subject = agentJsonWebKey.jwkThumbprint,
            subjectJwk = agentJsonWebKey,
            audience = params.parameters.redirectUrl ?: params.parameters.clientId ?: agentJsonWebKey.jwkThumbprint,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = params.parameters.nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        val signedIdToken = jwsService.createSignedJwsAddingParams(payload = jwsPayload, addX5c = false).getOrElse {
            Napier.w("Could not sign id_token", it)
            return KmmResult.failure(OAuth2Exception(Errors.USER_CANCELLED))
        }

        val presentationResultContainer = presentationDefinition?.let {
            holder.createPresentation(
                challenge = params.parameters.nonce,
                audienceId = audience,
                presentationDefinition = presentationDefinition,
                fallbackFormatHolder = presentationDefinition.formats ?: clientMetadata.vpFormats,
            ).getOrElse { exception ->
                return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.USER_CANCELLED))
                    .also { Napier.w("Could not create presentation: ${exception.message}") }
            }
        }
        presentationResultContainer?.let {
            clientMetadata.vpFormats?.let { supportedFormats ->
                presentationResultContainer.presentationSubmission.descriptorMap?.mapIndexed { index, descriptor ->
                    val isMissingFormatSupport = when (descriptor.format) {
                        ClaimFormatEnum.JWT_VP -> supportedFormats.jwtVp?.algorithms?.contains(jwsService.algorithm.identifier) != true

                        ClaimFormatEnum.JWT_SD -> supportedFormats.jwtSd?.algorithms?.contains(
                            jwsService.algorithm.identifier
                        ) != true

                        ClaimFormatEnum.MSO_MDOC -> supportedFormats.msoMdoc?.algorithms?.contains(
                            jwsService.algorithm.identifier
                        ) != true

                        else -> true
                    }

                    if (isMissingFormatSupport) {
                        return KmmResult.failure(
                            OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
                                .also { Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats") }
                        )
                    }
                }
            }
        }

        val vpToken = presentationResultContainer?.presentationResults?.map { it.toJsonPrimitive() }?.singleOrArray()
        return KmmResult.success(
            AuthenticationResponseParameters(
                idToken = signedIdToken.serialize(),
                state = params.parameters.state,
                vpToken = vpToken,
                presentationSubmission = presentationResultContainer?.presentationSubmission,
            )
        )
    }

    private fun verifyResponseModeDirectPost(params: AuthenticationRequestParametersFrom<*>) {
        if (params.parameters.redirectUrl != null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is ${params.parameters.responseMode}, but redirect_url is set") }
        if (params.parameters.responseUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is ${params.parameters.responseMode}, but response_url is not set") }
    }

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

    private fun List<JsonPrimitive>.singleOrArray() =
        if (size == 1) {
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
