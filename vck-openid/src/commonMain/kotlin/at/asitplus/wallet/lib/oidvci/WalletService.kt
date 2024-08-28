package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.signum.indispensable.cosef.CborWebToken
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.CREDENTIAL_TYPE_OPENID
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.wallet.lib.oidc.RemoteResourceRetrieverFunction
import at.asitplus.openid.RequestedCredentialClaimSpecification
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlin.random.Random

/**
 * Client service to retrieve credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
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
    private val cryptoService: CryptoService = DefaultCryptoService(RandomKeyPairAdapter()),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val coseService: CoseService = DefaultCoseService(cryptoService),
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
        keyPairAdapter: KeyPairAdapter,
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
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl]).
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
     * @param credential which credential from [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    suspend fun createAuthRequest(
        state: String,
        credential: Pair<String, SupportedCredentialFormat>,
        credentialIssuer: String? = null,
        authorizationServers: Set<String>? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        authorizationDetails = setOf(credential.toAuthnDetails(authorizationServers)),
        scope = credential.first,
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl]).
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
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     */
    suspend fun createAuthRequest(
        requestOptions: RequestOptions,
        credentialIssuer: String? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = requestOptions.state,
        clientId = clientId,
        authorizationDetails = requestOptions.toAuthnDetails()?.let { setOf(it) },
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(requestOptions.state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

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
         * Pre-auth code from [CredentialOfferGrants.preAuthorizedCode] in [CredentialOffer.grants]
         */
        data class PreAuthCode(val preAuth: CredentialOfferGrantsPreAuthCode) : AuthorizationForToken()
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl]).
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
            transactionCode = authorization.preAuth.transactionCode,
            preAuthorizedCode = authorization.preAuth.preAuthorizedCode,
            codeVerifier = stateToCodeStore.remove(requestOptions.state)
        )
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest], or pre-auth code.
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl]).
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
     * @param credential which credential from [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param requestedAttributes attributes that shall be requested explicitly (selective disclosure)
     * @param state used in [createAuthRequest], e.g. when using authorization codes
     * @param authorization for the token endpoint
     */
    suspend fun createTokenRequestParameters(
        credential: SupportedCredentialFormat,
        requestedAttributes: Set<String>? = null,
        state: String? = null,
        authorization: AuthorizationForToken,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(credential.toAuthnDetails(requestedAttributes)),
            codeVerifier = state?.let { stateToCodeStore.remove(it) }
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = setOf(credential.toAuthnDetails(requestedAttributes)),
            transactionCode = authorization.preAuth.transactionCode,
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
     * @param credential which credential from [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param requestedAttributes attributes that shall be requested explicitly (selective disclosure)
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequest(
        credential: SupportedCredentialFormat,
        requestedAttributes: Set<String>? = null,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        val cwtProofType = OpenIdConstants.ProofType.CWT.stringRepresentation
        val isCwt = credential.supportedProofTypes?.containsKey(cwtProofType) == true
                || credential.format == CredentialFormatEnum.MSO_MDOC
        val proof = if (isCwt) {
            createCredentialRequestCwt(null, clientNonce, credentialIssuer)
        } else {
            createCredentialRequestJwt(null, clientNonce, credentialIssuer)
        }
        credential.toCredentialRequestParameters(requestedAttributes, proof)
            .also { Napier.i("createCredentialRequest returns $it") }
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
        val proof = if (requestOptions.representation == ISO_MDOC) {
            createCredentialRequestCwt(requestOptions, clientNonce, credentialIssuer)
        } else {
            createCredentialRequestJwt(requestOptions, clientNonce, credentialIssuer)
        }
        requestOptions.toCredentialRequestParameters(proof)
            .also { Napier.i("createCredentialRequest returns $it") }
    }

    private suspend fun createCredentialRequestJwt(
        requestOptions: RequestOptions?,
        clientNonce: String?,
        credentialIssuer: String?,
    ): CredentialRequestProof = CredentialRequestProof(
        proofType = OpenIdConstants.ProofType.JWT,
        jwt = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = cryptoService.keyPairAdapter.signingAlgorithm.toJwsAlgorithm().getOrThrow(),
                type = OpenIdConstants.ProofType.JWT_HEADER_TYPE.stringRepresentation,
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

    private suspend fun createCredentialRequestCwt(
        requestOptions: RequestOptions?,
        clientNonce: String?,
        credentialIssuer: String?,
    ) = CredentialRequestProof(
        proofType = OpenIdConstants.ProofType.CWT,
        cwt = coseService.createSignedCose(
            protectedHeader = CoseHeader(
                algorithm = cryptoService.keyPairAdapter.signingAlgorithm.toCoseAlgorithm().getOrThrow(),
                contentType = OpenIdConstants.ProofType.CWT_HEADER_TYPE.stringRepresentation,
                certificateChain = cryptoService.keyPairAdapter.certificate?.encodeToDerOrNull()
            ),
            payload = CborWebToken(
                issuer = clientId, // omit when token was pre-authn?
                audience = credentialIssuer,
                issuedAt = requestOptions?.clock?.now() ?: Clock.System.now(),
                nonce = clientNonce?.encodeToByteArray(),
            ).serialize(),
            addKeyId = false,
        ).getOrThrow().serialize().encodeToString(Base64UrlStrict),
    )

    private fun RequestOptions.toCredentialRequestParameters(proof: CredentialRequestProof) =
        representation.toCredentialRequestParameters(credentialScheme, requestedAttributes, proof)

    private fun SupportedCredentialFormat.toAuthnDetails(requestedAttributes: Set<String>?) = when (this.format) {
        CredentialFormatEnum.JWT_VC -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            credentialDefinition = credentialDefinition
        )

        CredentialFormatEnum.VC_SD_JWT -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            sdJwtVcType = sdJwtVcType,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtVcType!!),
        )

        CredentialFormatEnum.MSO_MDOC -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            docType = docType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoClaims?.keys?.firstOrNull() ?: docType!!)
        )

        else -> throw IllegalArgumentException("Credential format $format not supported for AuthorizationDetails")
    }

    private fun RequestOptions.toAuthnDetails() =
        representation.toAuthorizationDetails(credentialScheme, requestedAttributes)

    private fun CredentialRepresentation.toAuthorizationDetails(
        scheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?
    ) = when (this) {
        PLAIN_JWT -> scheme.toJwtAuthn(toFormat())
        SD_JWT -> scheme.toSdJwtAuthn(toFormat(), requestedAttributes)
        ISO_MDOC -> scheme.toIsoAuthn(toFormat(), requestedAttributes)
    }

    private fun ConstantIndex.CredentialScheme.toJwtAuthn(
        format: CredentialFormatEnum
    ) = if (supportsVcJwt)
        AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType!!),
            ),
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?
    ) = if (supportsSdJwt)
        AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            sdJwtVcType = sdJwtType!!,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtType!!),
        ) else null

    private fun ConstantIndex.CredentialScheme.toIsoAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?
    ) = if (supportsIso)
        AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            docType = isoDocType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoNamespace!!)
        ) else null

    private fun CredentialRepresentation.toCredentialRequestParameters(
        credentialScheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?,
        proof: CredentialRequestProof
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
        proof: CredentialRequestProof
    ) = when (format) {
        CredentialFormatEnum.JWT_VC -> CredentialRequestParameters(
            format = format,
            credentialDefinition = credentialDefinition,
            proof = proof
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

private fun Pair<String, SupportedCredentialFormat>.toAuthnDetails(authorizationServers: Set<String>?)
        : AuthorizationDetails = AuthorizationDetails(
    type = "openid_credential",
    credentialConfigurationId = first,
    format = second.format,
    docType = second.docType,
    sdJwtVcType = second.sdJwtVcType,
    credentialDefinition = second.credentialDefinition,
    locations = authorizationServers
)

private fun Collection<String>.toRequestedClaimsSdJwt(sdJwtType: String) =
    mapOf(sdJwtType to this.associateWith { RequestedCredentialClaimSpecification() })

private fun Collection<String>.toRequestedClaimsIso(isoNamespace: String) =
    mapOf(isoNamespace to this.associateWith { RequestedCredentialClaimSpecification() })


private fun CredentialRepresentation.toFormat() = when (this) {
    PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    SD_JWT -> CredentialFormatEnum.VC_SD_JWT
    ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}
