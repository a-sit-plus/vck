package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
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
import at.asitplus.wallet.lib.agent.InputDescriptorCredentialSubmission
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import at.asitplus.wallet.lib.agent.toDefaultSubmission
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.FormatHolder
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
import at.asitplus.wallet.lib.oidc.helpers.AuthenticationResponseResultFactory
import at.asitplus.wallet.lib.oidc.helpers.ClientIdSchemeParametersFactory
import at.asitplus.wallet.lib.oidc.helpers.ResponseModeParameters
import at.asitplus.wallet.lib.oidc.helpers.ResponseModeParametersFactory
import at.asitplus.wallet.lib.oidvci.IssuerMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import io.github.aakira.napier.Napier
import io.ktor.http.Url
import io.ktor.util.flattenEntries
import io.matthewnelson.encoding.base16.Base16
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
    suspend fun parseAuthenticationRequestParameters(input: String): KmmResult<AuthenticationRequestParametersFrom<*>> {
        val parsedParams = kotlin.run { // maybe it is a request JWS
            parseRequestObjectJws(input)
        } ?: kotlin.runCatching { // maybe it's in the URL parameters
            Url(input).let {
                val params = it.parameters.flattenEntries().toMap()
                    .decodeFromUrlQuery<AuthenticationRequestParameters>()
                AuthenticationRequestParametersFrom.Uri(it, params)
            }
        }.onFailure { it.printStackTrace() }.getOrNull() ?: kotlin.runCatching {
            // maybe it is already a JSON string
            val params = AuthenticationRequestParameters.deserialize(input).getOrThrow()
            AuthenticationRequestParametersFrom.Json(input, params)
        }.getOrNull()

        if (parsedParams == null) {
            Napier.w("Could not parse authentication request: $input")
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
        }

        val extractedParams = parsedParams.let { extractRequestObject(it.parameters) ?: it }
            .also { Napier.i("parsed authentication request: $it") }
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
                    jwsSigned = jws,
                    parameters = params,
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
                .getOrElse { return KmmResult.failure(it) }

        val clientIdSchemeParameters =
            ClientIdSchemeParametersFactory(request).createClientIdSchemeParameters().getOrElse {
                return KmmResult.failure(it)
            }

        // TODO Check removed for EUDI interop
//        if (clientMetadata.subjectSyntaxTypesSupported == null || URN_TYPE_JWK_THUMBPRINT !in clientMetadata.subjectSyntaxTypesSupported) {
//            return KmmResult.failure<AuthenticationResponseBuilder>(OAuth2Exception(Errors.SUBJECT_SYNTAX_TYPES_NOT_SUPPORTED))
//                .also { Napier.w("Incompatible subject syntax types algorithms") }
//        }

        val clientMetadata = runCatching { request.parameters.loadClientMetadata() }.getOrElse {
            return KmmResult.failure(it)
        }
        val audience = runCatching { request.extractAudience(clientMetadata) }.getOrElse {
            return KmmResult.failure(it)
        }

        val presentationDefinition = request.parameters.loadPresentationDefinition()?.also {
            runCatching {
                verifyResponseTypeForPresentationDefinition(responseType)
            }.onFailure { return KmmResult.failure(it) }
        }

        val presentationPreparationState = presentationDefinition?.runCatching {
            PresentationPreparationState(
                presentationDefinition = presentationDefinition,
                fallbackFormatHolder = clientMetadata.vpFormats
            ).also {
                refreshPresentationPreparationState(it)
            }
        }?.getOrElse { exception ->
            exception.message?.also { Napier.w { it } }
            return KmmResult.failure(OAuth2Exception(Errors.INVALID_REQUEST))
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
                presentationPreparationState = presentationPreparationState,
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
        val response = finalizeAuthenticationResponseParameters(
            authenticationResponsePreparationState,
            inputDescriptorCredentialSubmissions = inputDescriptorCredentialSubmissions,
        ).getOrElse {
            return KmmResult.failure(it)
        }

        /* TODO: rectify authnResponseDirectPostJwt
                val responseSerialized = buildJarm(response)
        val jarm = AuthenticationResponseParameters(response = responseSerialized)
        return AuthenticationResponseResult.Post(url, jarm.encodeToParameters())

         */

        return AuthenticationResponseResultFactory(
            jwsService = jwsService,
            responseParameters = response,
            responseModeParameters = authenticationResponsePreparationState.responseModeParameters
        ).createAuthenticationResponseResult()
    }


    internal suspend fun finalizeAuthenticationResponseParameters(
        authenticationResponsePreparationState: AuthenticationResponsePreparationState,
        inputDescriptorCredentialSubmissions: Map<String, InputDescriptorCredentialSubmission>? = null,
    ): KmmResult<AuthenticationResponse> {
        val signedIdToken =
            if (!authenticationResponsePreparationState.responseType.contains(ID_TOKEN)) {
                null
            } else runCatching {
                buildSignedIdToken(
                    nonce = authenticationResponsePreparationState.nonce,
                    audience = authenticationResponsePreparationState.parameters.redirectUrl
                        ?: authenticationResponsePreparationState.parameters.clientId,
                )
            }.getOrElse { return KmmResult.failure(it) }

        val presentationResultContainer =
            authenticationResponsePreparationState.presentationPreparationState?.runCatching {
                buildPresentation(
                    authenticationResponsePreparationState = authenticationResponsePreparationState,
                    presentationPreparationState = this,
                    inputDescriptorCredentialSubmissions = inputDescriptorCredentialSubmissions
                )
            }?.getOrElse { return KmmResult.failure(it) }

        presentationResultContainer?.also {
            authenticationResponsePreparationState.clientMetadata.vpFormats?.runCatching {
                presentationResultContainer.verifyFormatSupport(this)
            }?.getOrElse {
                return KmmResult.failure(it)
            }
        }

        val certKey = // TODO: fix
            (authenticationResponsePreparationState.parameters as? AuthenticationRequestParametersFrom.JwsSigned)?.source?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val jsonWebKeySet = authenticationResponsePreparationState.clientMetadata.loadJsonWebKeySet()?.keys.combine(certKey)

        val vpToken = presentationResultContainer?.presentationResults?.map { it.toVerifiablePresentationToken() }
            ?.singleOrArray()
        val authenticationResponseParameters = AuthenticationResponseParameters(
            idToken = signedIdToken?.serialize(),
            state = authenticationResponsePreparationState.parameters.state,
            vpToken = vpToken,
            presentationSubmission = presentationResultContainer?.presentationSubmission,
        )
        return KmmResult.success(
            AuthenticationResponse(
                authenticationResponseParameters,
                authenticationResponsePreparationState.parameters,
                jsonWebKeySet,
            )
        )
    }

    private fun Holder.PresentationResponseParameters.verifyFormatSupport(supportedFormats: FormatHolder) =
        presentationSubmission.descriptorMap?.forEach { descriptor ->
            if (supportedFormats.isMissingFormatSupport(descriptor.format)) {
                Napier.w("Incompatible JWT algorithms for claim format ${descriptor.format}: $supportedFormats")
                throw OAuth2Exception(Errors.REGISTRATION_VALUE_NOT_SUPPORTED)
            }
        }

    private suspend fun buildPresentation(
        authenticationResponsePreparationState: AuthenticationResponsePreparationState,
        presentationPreparationState: PresentationPreparationState,
        inputDescriptorCredentialSubmissions: Map<String, InputDescriptorCredentialSubmission>?,
    ): Holder.PresentationResponseParameters {
        val credentialSubmissions = inputDescriptorCredentialSubmissions
            ?: presentationPreparationState.inputDescriptorMatches.toDefaultSubmission()

        presentationPreparationState.presentationSubmissionValidator.isValidSubmission(
            credentialSubmissions.keys
        ).also { isValidSubmission ->
            if (!isValidSubmission) {
                Napier.w("submission requirements are not satisfied")
                throw OAuth2Exception(Errors.USER_CANCELLED)
            }
        }

        return holder.createPresentation(
            challenge = authenticationResponsePreparationState.nonce,
            audienceId = authenticationResponsePreparationState.audience,
            presentationDefinitionId = presentationPreparationState.presentationDefinitionId,
            presentationSubmissionSelection = credentialSubmissions,
        ).getOrElse { exception ->
            Napier.w("Could not create presentation: ${exception.message}")
            throw OAuth2Exception(Errors.USER_CANCELLED)
        }
    }

    private suspend fun buildJarm(response: AuthenticationResponse) =
        if (response.clientMetadata.requestsEncryption()) {
            val alg = response.clientMetadata.authorizationEncryptedResponseAlg!!
            val enc = response.clientMetadata.authorizationEncryptedResponseEncoding!!
            val jwk = response.jsonWebKeys.first()
            jwsService.encryptJweObject(
                header = JweHeader(
                    algorithm = alg,
                    encryption = enc,
                    type = null,
                    agreementPartyVInfo = Random.Default.nextBytes(16), // TODO nonce from authn request
                    keyId = jwk.keyId,
                ),
                payload = response.params.serialize().encodeToByteArray(),
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

    private suspend fun buildSignedIdToken(
        audience: String?,
        nonce: String,
    ): JwsSigned {
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
        return jwsService.createSignedJwsAddingParams(payload = jwsPayload, addX5c = false)
            .getOrElse {
                Napier.w("Could not sign id_token", it)
                throw OAuth2Exception(Errors.USER_CANCELLED)
            }
    }

    private fun verifyResponseTypeForPresentationDefinition(responseType: String) {
        if (!responseType.contains(VP_TOKEN)) {
            Napier.w("vp_token not requested")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
    }

    private suspend fun AuthenticationRequestParameters.loadPresentationDefinition() =
        presentationDefinition ?: presentationDefinitionUrl?.let {
            remoteResourceRetriever.invoke(it)
        }?.let { PresentationDefinition.deserialize(it).getOrNull() } ?: scope?.split(" ")
            ?.firstNotNullOfOrNull {
                scopePresentationDefinitionRetriever.invoke(it)
            }

    private suspend fun AuthenticationRequestParametersFrom<*>.extractAudience(
        clientMetadata: RelyingPartyMetadata
    ) = clientMetadata.loadJsonWebKeySet()?.keys?.firstOrNull()?.identifier
        ?: (source as? AuthenticationRequestParametersFrom.JwsSigned)
            ?.source?.header?.certificateChain?.leaf?.let { parameters.clientId } //TODO is this even correct ????
        ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("Could not parse audience") }

    private suspend fun RelyingPartyMetadata.loadJsonWebKeySet() =
        this.jsonWebKeySet ?: jsonWebKeySetUrl?.let { remoteResourceRetriever.invoke(it) }
            ?.let { JsonWebKeySet.deserialize(it).getOrNull() }


    private suspend fun AuthenticationRequestParameters.loadClientMetadata() =
        clientMetadata ?: clientMetadataUri?.let { uri ->
            remoteResourceRetriever.invoke(uri)
                ?.let { RelyingPartyMetadata.deserialize(it).getOrNull() }
        } ?: run {
            Napier.w("client metadata is not specified in ${this}")
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }

    private fun FormatHolder.isMissingFormatSupport(claimFormatEnum: ClaimFormatEnum) =
        when (claimFormatEnum) {
            ClaimFormatEnum.JWT_VP -> jwtVp?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ClaimFormatEnum.JWT_SD -> jwtSd?.algorithms?.contains(jwsService.algorithm.identifier) != true
            ClaimFormatEnum.MSO_MDOC -> msoMdoc?.algorithms?.contains(jwsService.algorithm.identifier) != true
            else -> true
        }

    private fun Holder.CreatePresentationResult.toVerifiablePresentationToken() = when (this) {
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
typealias RequestObjectJwsVerifier = (jws: JwsSigned, authnRequest: AuthenticationRequestParameters) -> Boolean

private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> {
    return certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
}
