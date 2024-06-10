package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JweHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseMode.*
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
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlin.random.Random
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
            cryptoService: CryptoService = DefaultCryptoService(RandomKeyPairAdapter()),
            holder: Holder = HolderAgent(cryptoService),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            clock: Clock = Clock.System,
            clientId: String = "https://wallet.a-sit.at/",
            remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
            requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { jws, authnRequest -> true },
            scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = { null },
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.keyPairAdapter.publicKey,
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
            Napier.w("Could not parse authentication request: $input")
            return KmmResult.failure(it)
        }
        return createAuthnResponse(parameters)
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun parseAuthenticationRequestParameters(input: String)
            : KmmResult<AuthenticationRequestParametersFrom<*>> = catching {
        // maybe it is a request JWS
        val parsedParams = kotlin.run { parseRequestObjectJws(input) }
            ?: kotlin.runCatching { // maybe it's in the URL parameters
                Url(input).let {
                    val params = it.parameters.flattenEntries().toMap()
                        .decodeFromUrlQuery<AuthenticationRequestParameters>()
                    AuthenticationRequestParametersFrom.Uri(it, params)
                }
            }.onFailure { it.printStackTrace() }.getOrNull()
            ?: kotlin.runCatching {  // maybe it is already a JSON string
                val params = AuthenticationRequestParameters.deserialize(input).getOrThrow()
                AuthenticationRequestParametersFrom.Json(input, params)
            }.getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("Could not parse authentication request: $input") }

        val extractedParams = parsedParams.let { extractRequestObject(it.parameters) ?: it }
            .also { Napier.i("Parsed authentication request: $it") }
        extractedParams
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
                    .apply { Napier.w("parseRequestObjectJws: Deserialization failed", it) }
            }
            if (requestObjectJwsVerifier.invoke(jws, params))
                AuthenticationRequestParametersFrom.JwsSigned(jws, params)
            else null
                .also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
    }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which were either encoded as query params,
     * or JSON serialized as a JWT Request Object.
     */
    suspend fun createAuthnResponse(
        request: AuthenticationRequestParametersFrom<*>
    ): KmmResult<AuthenticationResponseResult> = catching {
        val response = createAuthnResponseParams(request).getOrThrow()
        if (request.parameters.responseType == null
            || (!request.parameters.responseType.contains(ID_TOKEN)
                    && !request.parameters.responseType.contains(VP_TOKEN))
        ) {
            Napier.w("createAuthnResponse: Unknown response_type ${request.parameters.responseType}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        when (request.parameters.responseMode) {
            DIRECT_POST -> authnResponseDirectPost(request, response)
            DIRECT_POST_JWT -> authnResponseDirectPostJwt(request, response)
            QUERY -> authnResponseQuery(request, response)
            FRAGMENT, null -> authnResponseFragment(request, response)
            is OTHER -> TODO()
        }
    }

    private fun authnResponseDirectPost(
        request: AuthenticationRequestParametersFrom<*>,
        response: AuthenticationResponse
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Post(url, response.params.encodeToParameters())
    }

    /**
     * Per OID4VP, the response may either be signed, or encrypted (never signed and encrypted!)
     */
    private suspend fun authnResponseDirectPostJwt(
        request: AuthenticationRequestParametersFrom<*>,
        response: AuthenticationResponse
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        val responseSerialized = buildJarm(request, response)
        val jarm = AuthenticationResponseParameters(response = responseSerialized)
        return AuthenticationResponseResult.Post(url, jarm.encodeToParameters())
    }

    private suspend fun buildJarm(request: AuthenticationRequestParametersFrom<*>, response: AuthenticationResponse) =
        if (response.clientMetadata != null && response.jsonWebKeys != null && response.clientMetadata.requestsEncryption()) {
            val alg = response.clientMetadata.authorizationEncryptedResponseAlg!!
            val enc = response.clientMetadata.authorizationEncryptedResponseEncoding!!
            val jwk = response.jsonWebKeys.first()
            val nonce = runCatching { request.parameters.nonce?.decodeToByteArray(Base64()) }.getOrNull()
                ?: runCatching { request.parameters.nonce?.encodeToByteArray() }.getOrNull()
                ?: Random.Default.nextBytes(16)
            val payload = response.params.serialize().encodeToByteArray()
            jwsService.encryptJweObject(
                header = JweHeader(
                    algorithm = alg,
                    encryption = enc,
                    type = null,
                    agreementPartyVInfo = nonce.encodeToByteArray(Base64()),
                    agreementPartyUInfo = Random.nextBytes(16),
                    keyId = jwk.keyId,
                ),
                payload = payload,
                recipientKey = jwk,
                jweAlgorithm = alg,
                jweEncryption = enc,
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        } else {
            jwsService.createSignedJwsAddingParams(
                payload = response.params.serialize().encodeToByteArray(), addX5c = false
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        }

    private fun RelyingPartyMetadata.requestsEncryption() =
        authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null

    private fun authnResponseQuery(
        request: AuthenticationRequestParametersFrom<*>,
        response: AuthenticationResponse
    ): AuthenticationResponseResult.Redirect {
        if (request.parameters.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        val url = URLBuilder(request.parameters.redirectUrl).apply {
            response.params.encodeToParameters().forEach {
                this.parameters.append(it.key, it.value)
            }
        }.buildString()
        return AuthenticationResponseResult.Redirect(url, response.params)
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    private fun authnResponseFragment(
        request: AuthenticationRequestParametersFrom<*>,
        response: AuthenticationResponse
    ): AuthenticationResponseResult.Redirect {
        if (request.parameters.redirectUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        val url = URLBuilder(request.parameters.redirectUrl)
            .apply { encodedFragment = response.params.encodeToParameters().formUrlEncode() }
            .buildString()
        return AuthenticationResponseResult.Redirect(url, response.params)
    }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: AuthenticationRequestParametersFrom<*>
    ): KmmResult<AuthenticationResponse> = catching {
        val clientIdScheme = params.parameters.clientIdScheme
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.REDIRECT_URI) {
            params.parameters.verifyClientMetadata()
        }
        if (params.parameters.responseMode.isAnyDirectPost()) {
            params.parameters.verifyResponseModeDirectPost()
        }
        if (clientIdScheme.isAnyX509()) {
            params.verifyClientIdSchemeX509()
        }

        val clientMetadata = runCatching { params.parameters.loadClientMetadata() }.getOrNull()
        val certKey = (params as? AuthenticationRequestParametersFrom.JwsSigned)
            ?.source?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val jsonWebKeySet = clientMetadata?.loadJsonWebKeySet()?.keys?.combine(certKey)
        val audience = params.extractAudience(clientMetadata)
        if (!clientIdScheme.isAnyX509()) {
            params.parameters.verifyRedirectUrl()
        }

        val idToken = buildSignedIdToken(params)?.serialize()
        val resultContainer = params.parameters.loadPresentationDefinition()?.let { presentationDefinition ->
            params.parameters.verifyResponseType(presentationDefinition)
            buildPresentation(params, audience, presentationDefinition, clientMetadata).also { container ->
                clientMetadata?.vpFormats?.let { supportedFormats ->
                    container.verifyFormatSupport(supportedFormats)
                }
            }
        }

        val vpToken = resultContainer?.presentationResults?.map { it.toJsonPrimitive() }?.singleOrArray()
        val presentationSubmission = resultContainer?.presentationSubmission

        val parameters = AuthenticationResponseParameters(
            state = params.parameters.state,
            idToken = idToken,
            vpToken = vpToken,
            presentationSubmission = presentationSubmission,
        )
        AuthenticationResponse(parameters, clientMetadata, jsonWebKeySet)
    }

    private fun Holder.PresentationResponseParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        presentationSubmission.descriptorMap?.mapIndexed { _, descriptor ->
            if (supportedFormats.isMissingFormatSupport(descriptor.format)) {
                Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                throw OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
            }
        }

    private suspend fun buildPresentation(
        params: AuthenticationRequestParametersFrom<*>,
        audience: String,
        presentationDefinition: PresentationDefinition,
        clientMetadata: RelyingPartyMetadata?
    ): Holder.PresentationResponseParameters {
        if (params.parameters.nonce == null) {
            Napier.w("nonce is null in ${params.parameters}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        return holder.createPresentation(
            challenge = params.parameters.nonce,
            audienceId = audience,
            presentationDefinition = presentationDefinition,
            fallbackFormatHolder = presentationDefinition.formats ?: clientMetadata?.vpFormats,
        ).getOrElse {
            Napier.w("Could not create presentation", it)
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }
    }

    private suspend fun buildSignedIdToken(params: AuthenticationRequestParametersFrom<*>): JwsSigned? {
        if (params.parameters.responseType?.contains(ID_TOKEN) != true) {
            return null
        }
        if (params.parameters.nonce == null) {
            Napier.w("nonce is null in ${params.parameters}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
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
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }
        return signedIdToken
    }

    private fun AuthenticationRequestParameters.verifyResponseType(presentationDefinition: PresentationDefinition?) {
        if (responseType == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_type is not specified") }
        if (!responseType.contains(VP_TOKEN) && presentationDefinition == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("vp_token not requested") }
    }

    private suspend fun AuthenticationRequestParameters.loadPresentationDefinition() =
        if (responseType?.contains(VP_TOKEN) == true) {
            presentationDefinition
                ?: presentationDefinitionUrl?.let {
                    remoteResourceRetriever.invoke(it)
                }?.let { PresentationDefinition.deserialize(it).getOrNull() }
                ?: scope?.split(" ")?.firstNotNullOfOrNull {
                    scopePresentationDefinitionRetriever?.invoke(it)
                }
        } else null

    private fun AuthenticationRequestParameters.verifyRedirectUrl() {
        if (redirectUrl != null) {
            if (clientId != redirectUrl)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id does not match redirect_uri") }
        }
    }

    private suspend fun AuthenticationRequestParametersFrom<*>.extractAudience(
        clientMetadata: RelyingPartyMetadata?
    ) = clientMetadata?.loadJsonWebKeySet()?.keys?.firstOrNull()?.identifier
        ?: parameters.clientId
        ?: parameters.audience
        ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("Could not parse audience") }

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet() =
        this.jsonWebKeySet ?: jsonWebKeySetUrl?.let { remoteResourceRetriever.invoke(it) }
            ?.let { JsonWebKeySet.deserialize(it).getOrNull() }

    private suspend fun AuthenticationRequestParameters.loadClientMetadata() = clientMetadata
        ?: clientMetadataUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
        } ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("client metadata is not specified in $this") }

    private fun OpenIdConstants.ClientIdScheme?.isAnyX509() =
        (this == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) || (this == OpenIdConstants.ClientIdScheme.X509_SAN_URI)

    private fun AuthenticationRequestParameters.verifyClientMetadata() {
        if (clientMetadata == null && clientMetadataUri == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("client_id_scheme is redirect_uri, but metadata is not set") }
    }

    private fun AuthenticationRequestParametersFrom<*>.verifyClientIdSchemeX509() {
        val clientIdScheme = parameters.clientIdScheme
        val responseModeIsDirectPost = parameters.responseMode.isAnyDirectPost()
        if (this !is AuthenticationRequestParametersFrom.JwsSigned
            || source.header.certificateChain == null
            || source.header.certificateChain!!.isEmpty()
        ) throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("client_id_scheme is $clientIdScheme, but metadata is not set and no x5c certificate chain is present in the original authn request") }
        //basic checks done
        val leaf = source.header.certificateChain!!.leaf
        if (leaf.tbsCertificate.extensions == null || leaf.tbsCertificate.extensions!!.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("client_id_scheme is $clientIdScheme, but no extensions were found in the leaf certificate") }
        }
        if (clientIdScheme == OpenIdConstants.ClientIdScheme.X509_SAN_DNS) {
            val dnsNames = leaf.tbsCertificate.subjectAlternativeNames?.dnsNames
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but no dnsNames were found in the leaf certificate") }

            if (!dnsNames.contains(parameters.clientId))
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any dnsName in the leaf certificate") }

            if (!responseModeIsDirectPost) {
                val parsedUrl = parameters.redirectUrl?.let { Url(it) }
                    ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
                //TODO  If the Wallet can establish trust in the Client Identifier authenticated through the certificate it may allow the client to freely choose the redirect_uri value
                if (parsedUrl.host != parameters.clientId)
                    throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("client_id_scheme is $clientIdScheme, but no redirect_url was provided") }
            }
        } else {
            val uris = leaf.tbsCertificate.subjectAlternativeNames?.uris
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but no URIs were found in the leaf certificate") }
            if (!uris.contains(parameters.clientId))
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match any URIs in the leaf certificate") }

            if (parameters.clientId != parameters.redirectUrl)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("client_id_scheme is $clientIdScheme, but client_id does not match redirect_uri") }
        }
    }

    private fun OpenIdConstants.ResponseMode?.isAnyDirectPost() = (this == DIRECT_POST) || (this == DIRECT_POST_JWT)

    private fun FormatHolder.isMissingFormatSupport(claimFormatEnum: ClaimFormatEnum) = when (claimFormatEnum) {
        ClaimFormatEnum.JWT_VP -> jwtVp?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) } ?: false
        ClaimFormatEnum.JWT_SD -> jwtSd?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) } ?: false
        ClaimFormatEnum.MSO_MDOC -> msoMdoc?.algorithms?.let { !it.contains(jwsService.algorithm.identifier) } ?: false
        else -> false
    }

    private fun AuthenticationRequestParameters.verifyResponseModeDirectPost() {
        if (redirectUrl != null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is $responseMode, but redirect_url is set") }
        if (responseUrl == null)
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("response_mode is $responseMode, but response_url is not set") }
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

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> {
    return certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
}
