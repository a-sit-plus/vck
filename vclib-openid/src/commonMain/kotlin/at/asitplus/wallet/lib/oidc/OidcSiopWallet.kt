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
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ResponseModes.DIRECT_POST_JWT
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
import io.ktor.http.*
import io.ktor.util.*
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
    private val requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { _, _ -> true }
) {
    companion object {
        fun newDefaultInstance(
            cryptoService: CryptoService = DefaultCryptoService(),
            holder: Holder = HolderAgent.newDefaultInstance(cryptoService),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            clock: Clock = Clock.System,
            clientId: String = "https://wallet.a-sit.at/",
            remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
            requestObjectJwsVerifier: RequestObjectJwsVerifier = RequestObjectJwsVerifier { jws, authnRequest -> true }
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            clock = clock,
            clientId = clientId,
            remoteResourceRetriever = remoteResourceRetriever,
            requestObjectJwsVerifier = requestObjectJwsVerifier
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
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<AuthenticationRequestParameters> {
        val parsedParams = kotlin.run { // maybe it is a request JWS
            parseRequestObjectJws(input)
        } ?: kotlin.runCatching { // maybe it's in the URL parameters
            Url(input).parameters.flattenEntries().toMap().decodeFromUrlQuery<AuthenticationRequestParameters>()
        }.getOrNull() ?: kotlin.runCatching {  // maybe it is already a JSON string
            AuthenticationRequestParameters.deserialize(input).getOrNull()
        }.getOrNull()
        ?: return KmmResult.failure<AuthenticationRequestParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
            .also { Napier.w("Could not parse authentication request: $input") }

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
            remoteResourceRetriever.invoke(uri)?.let { parseAuthenticationRequestParameters(it).getOrNull() }
        }

    private fun parseRequestObjectJws(requestObject: String): AuthenticationRequestParameters? {
        return JwsSigned.parse(requestObject)?.let { jws ->
            val params = AuthenticationRequestParameters.deserialize(jws.payload.decodeToString()).getOrElse {
                return null
                    .also { Napier.w("parseRequestObjectJws: Deserialization failed", it) }
            }
            if (requestObjectJwsVerifier.invoke(jws, params)) params else null
                .also { Napier.w("parseRequestObjectJws: Signature not verified for $jws") }
        }
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
                    KmmResult.success(AuthenticationResponseResult.Redirect(url, responseParams))
                }

                else -> {
                    // default for vp_token and id_token is fragment
                    if (request.redirectUrl == null)
                        return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
                    val url = URLBuilder(request.redirectUrl)
                        .apply { encodedFragment = responseParams.encodeToParameters().formUrlEncode() }
                        .buildString()
                    KmmResult.success(AuthenticationResponseResult.Redirect(url, responseParams))
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
        // TODO implement x509_san_dns, x509_san_uri, as implemented by EUDI verifier
        val clientMetadata = params.clientMetadata
            ?: params.clientMetadataUri?.let { uri ->
                remoteResourceRetriever.invoke(uri)?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
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
        // TODO Check removed for EUDI interop
//        if (clientMetadata.subjectSyntaxTypesSupported == null || URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported)
//            return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
//                .also { Napier.w("Incompatible subject syntax types algorithms") }
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
        if (clientMetadata.vpFormats != null) {
            if (clientMetadata.vpFormats.jwtVp != null
                && clientMetadata.vpFormats.jwtVp?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                .also { Napier.w("Incompatible JWT algorithms") }
            if (clientMetadata.vpFormats.jwtSd != null
                && clientMetadata.vpFormats.jwtSd?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
                .also { Napier.w("Incompatible JWT algorithms") }
            if (clientMetadata.vpFormats.msoMdoc != null
                && clientMetadata.vpFormats.msoMdoc?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ) return KmmResult.failure<AuthenticationResponseParameters>(OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED))
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
            audience = params.redirectUrl ?: params.clientId ?: agentJsonWebKey.jwkThumbprint,
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
            ?: params.presentationDefinition?.inputDescriptors?.map { it.id }?.firstOrNull()
        val requestedSchemes = mutableListOf<ConstantIndex.CredentialScheme>()
        if (requestedNamespace != null) {
            AttributeIndex.resolveIsoNamespace(requestedNamespace)?.let { requestedSchemes.add(it) }
            requestedAttributeTypes.forEach { requestedAttributeTyp ->
                AttributeIndex.resolveAttributeType(requestedAttributeTyp)?.let { requestedSchemes.add(it) }
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
        val requestedClaimsClean = stripNamespaces(requestedClaims, requestedSchemes)
        val vp = holder.createPresentation(
            challenge = params.nonce,
            audienceId = audience,
            credentialSchemes = requestedSchemes.toList().ifEmpty { null },
            requestedClaims = requestedClaimsClean.ifEmpty { null }
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

    private fun stripNamespaces(
        requestedClaims: List<String>,
        requestedSchemes: MutableList<ConstantIndex.CredentialScheme>
    ) = requestedClaims.map { claim ->
        // NOTE: To be replaced with JSONPath implementation
        var cleaned = claim
        requestedSchemes.forEach { scheme ->
            cleaned = cleaned.removePrefix("\$['${scheme.isoNamespace}']['").removeSuffix("']")
        }
        cleaned
    }

}

/**
 * Implementations need to fetch the url passed in, and return either the body, if there is one,
 * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
 */
typealias RemoteResourceRetrieverFunction = suspend (String) -> String?

/**
 * Implementations need to verify the passed [JwsSigned] and return its result
 */
fun interface RequestObjectJwsVerifier {
    operator fun invoke(jws: JwsSigned, authnRequest: AuthenticationRequestParameters): Boolean
}