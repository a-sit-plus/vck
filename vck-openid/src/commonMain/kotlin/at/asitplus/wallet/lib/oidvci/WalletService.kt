package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.rqes.RqesConstants
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.random.Random

/**
 * Client service to retrieve credentials using OID4VCI
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 14, 2024-08-21.
 */
class WalletService(
    /**
     * Used to create [AuthenticationRequestParameters], [TokenRequestParameters] and [CredentialRequestProof],
     * typically a URI.
     */
    private val clientId: String = "https://wallet.a-sit.at/app",
    /**
     * Used to create [AuthenticationRequestParameters] and [TokenRequestParameters].
     */
    private val redirectUrl: String = "$clientId/callback",
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof],
     * i.e. the holder key.
     */
    private val cryptoService: CryptoService = DefaultCryptoService(EphemeralKeyWithoutCert()),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    private val stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
) {

    constructor(
        clientId: String,
        redirectUrl: String,
        keyPairAdapter: KeyMaterial,
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
        stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
    ) : this(
        clientId = clientId,
        redirectUrl = redirectUrl,
        cryptoService = DefaultCryptoService(keyPairAdapter),
        remoteResourceRetriever = remoteResourceRetriever,
        stateToCodeStore = stateToCodeStore
    )

    data class RequestOptions(
        /**
         * Credential type to request
         */
        val credentialScheme: ConstantIndex.CredentialScheme,
        /**
         * Required representation, see [ConstantIndex.CredentialRepresentation]
         */
        val representation: CredentialRepresentation = PLAIN_JWT,
        /**
         * List of attributes that shall be requested explicitly (selective disclosure),
         * or `null` to make no restrictions
         */
        val requestedAttributes: Set<String>? = null,
        /**
         * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
         */
        val state: String = uuid4().toString(),
        /**
         * Modify clock for testing specific scenarios
         */
        val clock: Clock = Clock.System,
    )

    /**
     * Pass in the URL provided by the Credential Issuer,
     * which may contain a direct [CredentialOffer] or a URI pointing to it.
     */
    suspend fun parseCredentialOffer(input: String): KmmResult<CredentialOffer> = catching {
        catching {
            val params = Url(input).parameters.flattenEntries().toMap()
                .decodeFromUrlQuery<CredentialOfferUrlParameters>()
            params.credentialOffer?.let {
                CredentialOffer.deserialize(it).getOrThrow()
            } ?: params.credentialOfferUrl?.let { uri ->
                remoteResourceRetriever.invoke(uri)
                    ?.let { parseCredentialOffer(it).getOrNull() }
            }
        }.getOrNull() ?: catching {
            CredentialOffer.deserialize(input).getOrThrow()
        }.getOrNull() ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            .also { Napier.w("Could not parse credential offer from $input") }
    }

    /**
     * Build authorization details for use in [createAuthRequest].
     *
     *
     * @param credentialConfigurationId which credential (the key) from
     * [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    suspend fun buildAuthorizationDetails(
        credentialConfigurationId: String,
        authorizationServers: Set<String>? = null,
    ) = setOf(
        AuthorizationDetails.OpenIdCredential(
            credentialConfigurationId = credentialConfigurationId,
            locations = authorizationServers,
            // TODO Test in real-world settings, is this correct?
            credentialIdentifiers = setOf(credentialConfigurationId)
        )
    )

    /**
     * Build authorization details for use in [createAuthRequest].
     */
    suspend fun buildAuthorizationDetails(
        requestOptions: RequestOptions
    ) = setOfNotNull(requestOptions.toAuthnDetails())

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [OAuth2AuthorizationServerMetadata.authorizationEndpoint]).
     *
     * Sample ktor code:
     * ```
     * val credentialConfig = issuerMetadata.supportedCredentialConfigurations!!
     *     .entries.first { it.key == credentialOffer.configurationIds.first() }.toPair()
     * val authnRequest = client.createAuthRequest(
     *     state = state,
     *     credential = credentialConfig,
     *     credentialIssuer = issuerMetadata.credentialIssuer,
     *     authorizationServers = issuerMetadata.authorizationServers
     * )
     * val authnResponse = httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * val authn = AuthenticationResponseParameters.deserialize(authnResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param state to send to the server, for internal state keeping
     * @param scope which credential (the value `scope` from
     * [IssuerMetadata.supportedCredentialConfigurations]) to request
     * @param authorizationDetails from [buildAuthorizationDetails]
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     */
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>,
        scope: String? = null,
        credentialIssuer: String? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        authorizationDetails = authorizationDetails,
        scope = scope,
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [OAuth2AuthorizationServerMetadata.authorizationEndpoint]).
     *
     * Sample ktor code:
     * ```
     * val authnRequest = client.createAuthRequest(
     *     requestOptions = requestOptions,
     *     credentialIssuer = issuerMetadata.credentialIssuer,
     * )
     * val authnResponse = httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * val authn = AuthenticationResponseParameters.deserialize(authnResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param requestOptions which credential in which representation to request
     * @param authorizationDetails from [buildAuthorizationDetails]
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     */
    suspend fun createAuthRequest(
        requestOptions: RequestOptions,
        authorizationDetails: Set<AuthorizationDetails>,
        credentialIssuer: String? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = requestOptions.state,
        clientId = clientId,
        authorizationDetails = authorizationDetails,
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(requestOptions.state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    /**
     * CSC: Minimal implementation for CSC requests
     */
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: AuthorizationDetails,
        credentialIssuer: String? = null,
        requestUri: String? = null,
    ): AuthenticationRequestParameters =
        when (authorizationDetails) {
            is AuthorizationDetails.OpenIdCredential -> AuthenticationRequestParameters(
                responseType = GRANT_TYPE_CODE,
                state = state,
                clientId = clientId,
                authorizationDetails = setOf(authorizationDetails),
                resource = credentialIssuer,
                redirectUrl = redirectUrl,
                codeChallenge = generateCodeVerifier(state),
                codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
            )

            is AuthorizationDetails.CSCCredential -> AuthenticationRequestParameters(
                responseType = GRANT_TYPE_CODE,
                state = state,
                clientId = clientId,
                authorizationDetails = setOf(authorizationDetails),
                scope = RqesConstants.SCOPE,
                redirectUrl = redirectUrl,
                codeChallenge = generateCodeVerifier(state),
                codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
                requestUri = requestUri
            )
        }

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun generateCodeVerifier(state: String): String {
        val codeVerifier = Random.nextBytes(32).toHexString(HexFormat.Default)
        stateToCodeStore.put(state, codeVerifier)
        return codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
    }

    sealed class AuthorizationForToken {
        /**
         * Authorization code from an actual OAuth2 Authorization Server, or [SimpleAuthorizationService.authorize]
         */
        data class Code(val code: String) : AuthorizationForToken()

        /**
         * Pre-auth code from [CredentialOfferGrants.preAuthorizedCode] in [CredentialOffer.grants],
         * optionally with a [transactionCode] which is transmitted out-of-band, and may be entered by the user.
         */
        data class PreAuthCode(
            val preAuth: CredentialOfferGrantsPreAuthCode,
            val transactionCode: String? = null
        ) : AuthorizationForToken()
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [OAuth2AuthorizationServerMetadata.tokenEndpoint]).
     *
     * Sample ktor code for authorization code:
     * ```
     * val authnRequest = client.createAuthRequest(requestOptions)
     * val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
     * val code = authnResponse.params.code
     * val tokenRequest = client.createTokenRequestParameters(requestOptions, code = code)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Sample ktor code for pre-authn code:
     * ```
     * val tokenRequest =
     *     client.createTokenRequestParameters(requestOptions, credentialOffer.grants!!.preAuthorizedCode)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Be sure to include a DPoP header if [IssuerMetadata.dpopSigningAlgValuesSupported] is set,
     * see [JwsService.buildDPoPHeader].
     *
     * @param requestOptions which credential in which representation to request
     * @param authorization for the token endpoint
     */
    suspend fun createTokenRequestParameters(
        requestOptions: RequestOptions,
        authorization: AuthorizationForToken,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = requestOptions.toAuthnDetails()?.let { setOf(it) },
            codeVerifier = stateToCodeStore.remove(requestOptions.state)
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = (requestOptions.toAuthnDetails())?.let { setOf(it) },
            transactionCode = authorization.transactionCode,
            preAuthorizedCode = authorization.preAuth.preAuthorizedCode,
            codeVerifier = stateToCodeStore.remove(requestOptions.state)
        )
    }

    /**
     * CSC: Minimal implementation for CSC requests.
     */
    suspend fun createTokenRequestParameters(
        state: String,
        authorizationDetails: AuthorizationDetails,
        authorization: AuthorizationForToken,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(authorizationDetails),
            codeVerifier = stateToCodeStore.remove(state)
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(authorizationDetails),
            transactionCode = authorization.transactionCode,
            preAuthorizedCode = authorization.preAuth.preAuthorizedCode,
            codeVerifier = stateToCodeStore.remove(state)
        )
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [OAuth2AuthorizationServerMetadata.tokenEndpoint]).
     *
     * Sample ktor code for authorization code:
     * ```
     * val authnRequest = client.createAuthRequest(requestOptions)
     * val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
     * val code = authnResponse.params.code
     * val tokenRequest = client.createTokenRequestParameters(requestOptions, code = code)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Sample ktor code for pre-authn code:
     * ```
     * val tokenRequest =
     *     client.createTokenRequestParameters(requestOptions, credentialOffer.grants!!.preAuthorizedCode)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * Be sure to include a DPoP header if [IssuerMetadata.dpopSigningAlgValuesSupported] is set,
     * see [JwsService.buildDPoPHeader].
     *
     * @param credentialConfigurationId which credential (the key) from
     * [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param state used in [createAuthRequest], e.g. when using authorization codes
     * @param authorization for the token endpoint
     */
    suspend fun createTokenRequestParameters(
        credentialConfigurationId: String,
        state: String? = null,
        authorization: AuthorizationForToken,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(
                AuthorizationDetails.OpenIdCredential(
                    credentialConfigurationId = credentialConfigurationId,
                )
            ),
            codeVerifier = state?.let { stateToCodeStore.remove(it) }
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(
                AuthorizationDetails.OpenIdCredential(
                    credentialConfigurationId = credentialConfigurationId,
                )
            ),
            transactionCode = authorization.transactionCode,
            preAuthorizedCode = authorization.preAuth.preAuthorizedCode,
            codeVerifier = state?.let { stateToCodeStore.remove(it) }
        )
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     *
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     * See [createTokenRequestParameters].
     *
     * Sample ktor code:
     * ```
     * val credentialRequest = client.createCredentialRequestJwt(
     *     requestOptions = requestOptions,
     *     clientNonce = token.clientNonce,
     *     credentialIssuer = issuerMetadata.credentialIssuer
     * ).getOrThrow()
     *
     * val credentialResponse = httpClient.post(issuerMetadata.credentialEndpointUrl) {
     *     setBody(credentialRequest)
     *     headers {
     *         append(HttpHeaders.Authorization, "Bearer ${token.accessToken}")
     *     }
     * }
     * ```
     *
     * Be sure to include a DPoP header if [TokenResponseParameters.tokenType] is `DPoP`,
     * see [JwsService.buildDPoPHeader].
     *
     * @param authorizationDetails from the token response, see [TokenResponseParameters.authorizationDetails]
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequest(
        authorizationDetails: AuthorizationDetails.OpenIdCredential,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        CredentialRequestParameters(
            credentialIdentifier = authorizationDetails.credentialConfigurationId,
            proof = createCredentialRequestJwt(null, clientNonce, credentialIssuer),
        ).also { Napier.i("createCredentialRequest returns $it") }
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     *
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     * See [createTokenRequestParameters].
     *
     * Sample ktor code:
     * ```
     * val credentialRequest = client.createCredentialRequestJwt(
     *     requestOptions = requestOptions,
     *     clientNonce = token.clientNonce,
     *     credentialIssuer = issuerMetadata.credentialIssuer
     * ).getOrThrow()
     *
     * val credentialResponse = httpClient.post(issuerMetadata.credentialEndpointUrl) {
     *     setBody(credentialRequest)
     *     headers {
     *         append(HttpHeaders.Authorization, "Bearer ${token.accessToken}")
     *     }
     * }
     * ```
     *
     * @param requestOptions which credential in which representation to request
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequest(
        requestOptions: RequestOptions,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        val proof = createCredentialRequestJwt(requestOptions, clientNonce, credentialIssuer)
        requestOptions.toCredentialRequestParameters(proof)
            .also { Napier.i("createCredentialRequest returns $it") }
    }

    internal suspend fun createCredentialRequestJwt(
        requestOptions: RequestOptions?,
        clientNonce: String?,
        credentialIssuer: String?,
    ): CredentialRequestProof = CredentialRequestProof(
        proofType = OpenIdConstants.ProofType.JWT,
        jwt = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
                type = OpenIdConstants.PROOF_JWT_TYPE
            ),
            payload = JsonWebToken(
                issuer = clientId, // omit when token was pre-authn?
                audience = credentialIssuer,
                issuedAt = requestOptions?.clock?.now() ?: Clock.System.now(),
                nonce = clientNonce,
            ).serialize().encodeToByteArray(),
            addKeyId = false,
            addJsonWebKey = true,
            addX5c = false,
        ).getOrThrow().serialize()
    )

    private fun RequestOptions.toCredentialRequestParameters(proof: CredentialRequestProof) =
        representation.toCredentialRequestParameters(credentialScheme, requestedAttributes, proof)

    private fun RequestOptions.toAuthnDetails() =
        representation.toAuthorizationDetails(credentialScheme, requestedAttributes)

    private fun CredentialRepresentation.toAuthorizationDetails(
        scheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?,
    ) = when (this) {
        PLAIN_JWT -> scheme.toJwtAuthn(toFormat())
        SD_JWT -> scheme.toSdJwtAuthn(toFormat(), requestedAttributes)
        ISO_MDOC -> scheme.toIsoAuthn(toFormat(), requestedAttributes)
    }

    private fun ConstantIndex.CredentialScheme.toJwtAuthn(
        format: CredentialFormatEnum,
    ) = if (supportsVcJwt)
        AuthorizationDetails.OpenIdCredential(
            format = format,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType!!),
            ),
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?,
    ) = if (supportsSdJwt)
        AuthorizationDetails.OpenIdCredential(
            format = format,
            sdJwtVcType = sdJwtType!!,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtType!!),
        ) else null

    private fun ConstantIndex.CredentialScheme.toIsoAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?,
    ) = if (supportsIso)
        AuthorizationDetails.OpenIdCredential(
            format = format,
            docType = isoDocType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoNamespace!!)
        ) else null

    private fun CredentialRepresentation.toCredentialRequestParameters(
        credentialScheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?,
        proof: CredentialRequestProof,
    ) = when {
        this == PLAIN_JWT && credentialScheme.supportsVcJwt -> CredentialRequestParameters(
            format = toFormat(),
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType!!,
            ),
            proof = proof
        )

        this == SD_JWT && credentialScheme.supportsSdJwt -> CredentialRequestParameters(
            format = toFormat(),
            sdJwtVcType = credentialScheme.sdJwtType!!,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(credentialScheme.sdJwtType!!),
            proof = proof
        )

        this == ISO_MDOC && credentialScheme.supportsIso -> CredentialRequestParameters(
            format = toFormat(),
            docType = credentialScheme.isoDocType,
            claims = requestedAttributes?.toRequestedClaimsIso(credentialScheme.isoNamespace!!),
            proof = proof
        )

        else -> throw IllegalArgumentException("format $this not applicable to $credentialScheme")
    }

    private fun SupportedCredentialFormat.toCredentialRequestParameters(
        requestedAttributes: Set<String>?,
        proof: CredentialRequestProof,
        authorizationDetails: AuthorizationDetails.OpenIdCredential?,
    ) = when (format) {
        CredentialFormatEnum.JWT_VC -> CredentialRequestParameters(
            credentialIdentifier = authorizationDetails?.credentialConfigurationId,
            format = format,
            credentialDefinition = credentialDefinition,
            proof = proof,
        )

        CredentialFormatEnum.VC_SD_JWT -> CredentialRequestParameters(
            format = format,
            sdJwtVcType = sdJwtVcType,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtVcType!!),
            proof = proof
        )

        CredentialFormatEnum.MSO_MDOC -> CredentialRequestParameters(
            format = format,
            docType = docType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoClaims?.keys?.firstOrNull() ?: docType!!),
            proof = proof
        )

        else -> throw IllegalArgumentException("format $format not applicable to create credential request")
    }
}

private fun Collection<String>.toRequestedClaimsSdJwt(sdJwtType: String) =
    mapOf(sdJwtType to this.associateWith { RequestedCredentialClaimSpecification() })

private fun Collection<String>.toRequestedClaimsIso(isoNamespace: String) =
    mapOf(isoNamespace to this.associateWith { RequestedCredentialClaimSpecification() })


private fun CredentialRepresentation.toFormat() = when (this) {
    PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    SD_JWT -> CredentialFormatEnum.VC_SD_JWT
    ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}

/**
 * To be set as header `DPoP` in making request to [url],
 * see [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
 */
suspend fun JwsService.buildDPoPHeader(
    url: String,
    httpMethod: String = "POST",
    accessToken: String? = null
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.DPOP_JWT
    ),
    payload = JsonWebToken(
        jwtId = Random.nextBytes(12).encodeToString(Base64UrlStrict),
        httpMethod = httpMethod,
        httpTargetUrl = url,
        accessTokenHash = accessToken?.encodeToByteArray()?.sha256()?.encodeToString(Base64UrlStrict),
        issuedAt = Clock.System.now(),
    ).serialize().encodeToByteArray(),
    addKeyId = false,
    addJsonWebKey = true,
    addX5c = false,
).getOrThrow().serialize()
