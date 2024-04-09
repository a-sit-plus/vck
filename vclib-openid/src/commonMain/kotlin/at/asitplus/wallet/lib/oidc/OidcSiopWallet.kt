package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST
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
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
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
     * or the authentication request itself as `request_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /**
     * Need to verify the request object serialized as a JWS,
     * which may be signed with a pre-registered key (see [OpenIdConstants.ClientIdSchemes.PRE_REGISTERED]).
     */
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _, _ -> true },
    /**
     * Need to implement if the presentation definition needs to be derived from a scope value.
     * See [ScopePresentationDefinitionRetriever] for implementation instructions.
     */
    private val scopePresentationDefinitionRetriever: ScopePresentationDefinitionRetriever? = null,
) {
    companion object {
        fun newInstance(
            holder: Holder,
            cryptoService: CryptoService,
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

    /**
     * Possible outcomes of creating the OIDC Authentication Response
     */
    sealed class AuthenticationResponseResult {
        /**
         * Wallet returns the [AuthenticationResponseParameters] as form parameters, which shall be posted to
         * `redirect_uri of the Relying Party, i.e. clients should execute that POST with [params] to [url].
         */
        data class Post(val url: String, val params: Map<String, String>) :
            AuthenticationResponseResult()

        /**
         * Wallet returns the [AuthenticationResponseParameters] as fragment parameters appended to the
         * `redirect_uri` of the Relying Party, i.e. clients should simply open the [url].
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
        return createAuthnResponse(retrieveAuthenticationRequestParameters(input))
    }

    /**
     * Pass in the URL sent by the Verifier (containing the [AuthenticationRequestParameters] as query parameters),
     * to create [AuthenticationResponseParameters] that can be sent back to the Verifier, see
     * [AuthenticationResponseResult].
     */
    suspend fun retrieveAuthenticationRequestParameters(input: String): AuthenticationRequestParameters {
        val params = kotlin.runCatching {
            // maybe it's already a request jws?
            parseRequestObjectJws(input)
        }.getOrNull() ?: kotlin.runCatching {
            // maybe it's a url that already encodes the authentication request as url parameters
            Url(input).parameters.flattenEntries().toMap()
                .decodeFromUrlQuery<AuthenticationRequestParameters>()
        }.getOrNull() ?: kotlin.runCatching {
            // maybe it's a url that yields the request object in some other way
            remoteResourceRetriever.invoke(input)
                ?.let { retrieveAuthenticationRequestParameters(it) }
        }.getOrNull()
        ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
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
            val authnRequestParams = kotlin.runCatching {
                AuthenticationRequestParameters.deserialize(jws.payload.decodeToString())
            }.getOrNull() ?: return null
            val signatureVerified = requestObjectJwsVerifier.invoke(jws, authnRequestParams)
            if (!signatureVerified) {
                Napier.w("parseRequestObjectJws: Signature not verified for $jws")
                return null
            }
            return authnRequestParams
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
            return when (request.responseMode) {
                DIRECT_POST -> {
                    val url = request.responseUrl
                        ?: request.redirectUrl
                        ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                    KmmResult.success(
                        AuthenticationResponseResult.Post(
                            url = url,
                            params = responseParams.encodeToParameters()
                        )
                    )
                }

                DIRECT_POST_JWT -> {
                    val url = request.responseUrl
                        ?: request.redirectUrl
                        ?: return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                    jwsService.createSignedJwsAddingParams(
                        payload = responseParams.serialize().encodeToByteArray()
                    ).fold(
                        onSuccess = { responseParamsJws ->
                            val jarm =
                                AuthenticationResponseParameters(response = responseParamsJws.serialize())
                            KmmResult.success(
                                AuthenticationResponseResult.Post(
                                    url = url,
                                    params = jarm.encodeToParameters()
                                )
                            )
                        },
                        onFailure = {
                            KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                        }
                    )

                }

                QUERY -> {
                    if (request.redirectUrl == null)
                        return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                    val url = URLBuilder(request.redirectUrl)
                        .apply {
                            responseParams.encodeToParameters().forEach {
                                this.parameters.append(it.key, it.value)
                            }
                        }
                        .buildString()
                    KmmResult.success(AuthenticationResponseResult.Redirect(url))
                }

                else -> {
                    // default for vp_token and id_token is fragment
                    if (request.redirectUrl == null)
                        return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                    val url = URLBuilder(request.redirectUrl)
                        .apply {
                            encodedFragment = responseParams.encodeToParameters().formUrlEncode()
                        }
                        .buildString()
                    KmmResult.success(AuthenticationResponseResult.Redirect(url))
                }
            }
        },
        onFailure = {
            KmmResult.failure(it)
        }
    )

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(
        params: AuthenticationRequestParameters
    ): KmmResult<AuthenticationResponseParameters> {
        if (params.clientIdScheme == OpenIdConstants.ClientIdSchemes.REDIRECT_URI
            && (params.clientMetadata == null && params.clientMetadataUri == null)
        ) {
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client_id_scheme is redirect_uri, but metadata is not set") }
        }
        val clientMetadata = params.clientMetadata
            ?: params.clientMetadataUri?.let { uri ->
                remoteResourceRetriever.invoke(uri)?.let { RelyingPartyMetadata.deserialize(it) }
            }
            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("client metadata is not specified") }
        val audience = clientMetadata.jsonWebKeySet?.keys?.firstOrNull()?.identifier
            ?: clientMetadata.jsonWebKeySetUrl?.let {
                remoteResourceRetriever.invoke(it)
                    ?.let { JsonWebKeySet.deserialize(it) }?.keys?.firstOrNull()?.identifier
            }
            ?: return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("Could not parse audience") }
        if (URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported)
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
                .also { Napier.w("Incompatible subject syntax types algorithms") }
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

        val presentationDefinition =
            params.presentationDefinition ?: params.presentationDefinitionUri?.let {
                remoteResourceRetriever(it)?.let {
                    jsonSerializer.decodeFromString<PresentationDefinition>(it)
                }
            } ?: params.scope?.split(" ")?.firstNotNullOfOrNull {
                scopePresentationDefinitionRetriever?.invoke(it)
            } ?: throw OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
                .also { Napier.d("No valid presentation definition has been found for request $params") }

        val presentationSubmissionContainer = holder.createPresentation(
            challenge = params.nonce,
            audienceId = audience,
            presentationDefinition = presentationDefinition,
        ).getOrElse { exception ->
            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.USER_CANCELLED))
                .also { Napier.w("Could not create presentation: ${exception.message}") }
        }

        clientMetadata.vpFormats?.let { supportedFormats ->
            presentationSubmissionContainer.presentationSubmission.descriptorMap?.mapIndexed { index, descriptor ->
                val isMissingFormatSupport = when (descriptor.format) {
                    ClaimFormatEnum.JWT -> supportedFormats.jwt?.algorithms?.contains(jwsService.algorithm.identifier) != true
                    ClaimFormatEnum.JWT_VC -> supportedFormats.jwtVc?.algorithms?.contains(
                        jwsService.algorithm.identifier
                    ) != true

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
                    return KmmResult.failure(
                        OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
                            .also { Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $presentationDefinition") }
                    )
                }
            }
        }

        return KmmResult.success(
            AuthenticationResponseParameters(
                idToken = signedIdToken.serialize(),
                state = params.state,
                vpToken = presentationSubmissionContainer.verifiablePresentations.map {
                    when (it) {
                        is Holder.CreatePresentationResult.Signed -> it.jws
                        is Holder.CreatePresentationResult.SdJwt -> it.sdJwt
                        is Holder.CreatePresentationResult.Document -> it.document.serialize()
                            .encodeToString(
                                Base16(strict = true)
                            )
                    }
                }.let {
                    if (it.size == 1) JsonPrimitive(it[0])
                    else buildJsonArray {
                        for (value in it) {
                            add(value)
                        }
                    }
                },
                presentationSubmission = presentationSubmissionContainer.presentationSubmission,
            )
        )
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