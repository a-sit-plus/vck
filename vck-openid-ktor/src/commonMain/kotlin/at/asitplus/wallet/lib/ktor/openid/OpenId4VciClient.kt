package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.PARAMETER_PROMPT
import at.asitplus.openid.OpenIdConstants.PARAMETER_PROMPT_LOGIN
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Holder.StoreCredentialInput.*
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oauth2.OAuth2Client.AuthorizationForToken
import at.asitplus.wallet.lib.oidvci.*
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.util.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.Serializable
import kotlin.time.Duration.Companion.minutes


/**
 * Implements the client side of
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 *  * , Draft 15, 2024-12-19.
 *
 * Supported features:
 *  * Pre-authorized grants
 *  * Authentication code flows
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 */
class OpenId4VciClient(
    /** Used to continue authentication in a web browser, be sure to call back this service at [resumeWithAuthCode]. */
    private val openUrlExternally: suspend (String) -> Unit,
    /** ktor engine to use to make requests to issuing service. */
    engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     */
    cookiesStorage: CookiesStorage? = null,
    /** Additional configuration for building the HTTP client, e.g. callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /** Store context before jumping to an external browser with [openUrlExternally]. */
    private val storeProvisioningContext: suspend (ProvisioningContext) -> Unit,
    /** Load context after resuming with auth code in [resumeWithAuthCode]. */
    private val loadProvisioningContext: suspend () -> ProvisioningContext?,
    /**
     * Callback to load the client attestation JWT, which may be needed as authentication at the AS, where the
     * `clientId` must match [WalletService.clientId] in [oid4vciService] and the key attested in `cnf` must match
     * the key behind [clientAttestationJwsService], see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
     * .
     */
    private val loadClientAttestationJwt: suspend () -> String,
    /** Used for authenticating the client at the authorization server with client attestation. */
    private val clientAttestationJwsService: JwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert())),
    /** Used to calculate DPoP, i.e. the key the access token and refresh token gets bound to. */
    private val dpopJwsService: JwsService = DefaultJwsService(DefaultCryptoService(EphemeralKeyWithoutCert())),
    /**
     * Implements OID4VCI protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works, `cryptoService` provides proof of possession for credential key material.
     */
    val oid4vciService: WalletService = WalletService(),
    /** Final callback upon receiving credentials from the issuing service. */
    private val storeCredential: (suspend (Holder.StoreCredentialInput) -> Unit),
    /** Callback to store refresh tokens received from the AS, to refresh credentials sometime late. */
    private val storeRefreshToken: suspend (RefreshTokenInfo) -> Unit,
) {
    private val client: HttpClient = HttpClient(engine) {
        followRedirects = false
        install(ContentNegotiation) {
            json(vckJsonSerializer)
        }
        install(DefaultRequest) {
            header(HttpHeaders.ContentType, ContentType.Application.Json)
        }
        httpClientConfig?.let { apply(it) }
        install(HttpCookies) {
            cookiesStorage?.let {
                storage = it
            }
        }
    }

    /**
     * Loads credential metadata info from [host], parses it, returns list of [CredentialIdentifierInfo].
     */
    suspend fun loadCredentialMetadata(
        host: String,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        Napier.i("loadCredentialMetadata: $host")
        val issuerMetadata = client
            .get("$host${OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER}")
            .body<IssuerMetadata>()
        val supported = issuerMetadata.supportedCredentialConfigurations
            ?: throw Exception("No supported credential configurations")
        supported.map {
            CredentialIdentifierInfo(
                issuerMetadata = issuerMetadata,
                credentialIdentifier = it.key,
                supportedCredentialFormat = it.value
            )
        }.also {
            Napier.i("loadCredentialMetadata for $host returns $it")
        }
    }

    private fun SupportedCredentialFormat.resolveCredentialScheme(): ConstantIndex.CredentialScheme? =
        (credentialDefinition?.types?.firstNotNullOfOrNull { AttributeIndex.resolveAttributeType(it) }
            ?: sdJwtVcType?.let { AttributeIndex.resolveSdJwtAttributeType(it) }
            ?: docType?.let { AttributeIndex.resolveIsoDoctype(it) })

    @Deprecated(
        "Removed in OID4VCI draft 15",
        ReplaceWith("startProvisioningWithAuthRequest(credentialIssuer, credentialIdentifierInfo)")
    )
    suspend fun startProvisioningWithAuthRequest(
        credentialIssuer: String,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        @Suppress("unused") requestedAttributes: Set<NormalizedJsonPath>?,
    ) = startProvisioningWithAuthRequest(
        credentialIssuerUrl = credentialIssuer,
        credentialIdentifierInfo = credentialIdentifierInfo
    )

    /**
     * Starts the issuing process at [credentialIssuerUrl].
     * This will call [openUrlExternally] to perform authentication at the authorization server, typically in an
     * external browser to show appropriate user interface.
     * Clients need to call [resumeWithAuthCode] after getting the authorization code back from the authorization
     * server, e.g. by the Wallet app getting opened (see `redirectUrl` at [oid4vciService]) after the browser being
     * redirecting back from the authorization server.
     *
     * @param credentialIssuerUrl URL of the credential issuer service
     * @param credentialIdentifierInfo credential to request, i.e. picked by user selection
     */
    suspend fun startProvisioningWithAuthRequest(
        credentialIssuerUrl: String,
        credentialIdentifierInfo: CredentialIdentifierInfo,
    ): KmmResult<Unit> = catching {
        Napier.i("startProvisioningWithAuthRequest: $credentialIssuerUrl with $credentialIdentifierInfo")

        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull()
            ?: credentialIssuerUrl
        val oauthMetadata = client
            .get("$authorizationServer${OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION}")
            .body<OAuth2AuthorizationServerMetadata>()

        val state = uuid4().toString()
        ProvisioningContext(
            state = state,
            credential = credentialIdentifierInfo,
            oauthMetadata = oauthMetadata,
            issuerMetadata = issuerMetadata
        ).let {
            storeProvisioningContext.invoke(it)
            Napier.i("Store context: $it")
        }

        openAuthRequestInBrowser(
            state = state,
            scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
            authorizationDetails = oid4vciService.buildAuthorizationDetails(
                credentialIdentifierInfo.credentialIdentifier,
                issuerMetadata.authorizationServers
            ),
            credentialIssuer = credentialIssuerUrl,
            issuerState = null,
            oauthMetadata = oauthMetadata
        )
    }

    /**
     * Called after getting the redirect back from the authorization server to the credential issuer.
     *
     * Will request a token, and use that token to request a credential and store it.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * @param url the URL as it has been redirected back from the authorization server, i.e. containing param `code`
     */
    @Throws(Exception::class)
    suspend fun resumeWithAuthCode(
        url: String,
    ): KmmResult<Unit> = catching {
        Napier.i("resumeWithAuthCode")
        Napier.d("resumeWithAuthCode: $url")
        val context = loadProvisioningContext()
            ?: throw Exception("No provisioning context")

        val authnResponse = Url(url).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationResponseParameters>()
        val code = authnResponse.code
            ?: throw Exception("No authn code in $url")

        val hasScope = context.credential.supportedCredentialFormat.scope != null
        val tokenResponse = postToken(
            oauthMetadata = context.oauthMetadata,
            issuerMetadata = context.issuerMetadata,
            tokenRequest = oid4vciService.oauth2Client.createTokenRequestParameters(
                state = context.state,
                authorization = AuthorizationForToken.Code(code),
                scope = context.credential.supportedCredentialFormat.scope,
                authorizationDetails = if (!hasScope) oid4vciService.buildAuthorizationDetails(
                    context.credential.credentialIdentifier,
                    context.issuerMetadata.authorizationServers
                ) else null
            ),
        )
        Napier.i("Received token response")
        Napier.d("Received token response $tokenResponse")

        val credentialScheme = context.credential.supportedCredentialFormat.resolveCredentialScheme()
            ?: throw Exception("Unknown credential scheme in ${context.credential}")

        postCredentialRequestAndStore(
            issuerMetadata = context.issuerMetadata,
            oauthMetadata = context.oauthMetadata,
            tokenResponse = tokenResponse,
            credentialFormat = context.credential.supportedCredentialFormat,
            credentialIdentifier = context.credential.credentialIdentifier,
            credentialScheme = credentialScheme,
            previouslyRequestedScope = context.credential.supportedCredentialFormat.scope,
        )
    }

    /**
     * Call to refresh a credential with a stored refresh token (that was received when issuing the credential
     * for the first time, stored with [storeRefreshToken]).
     *
     * Will request a new access token, and use that token to request the same credential again and store it.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     */
    @Throws(Exception::class)
    suspend fun refreshCredential(
        refreshTokenInfo: RefreshTokenInfo,
    ): KmmResult<Unit> = catching {
        with(refreshTokenInfo) {
            Napier.i("refreshCredential")
            Napier.d("refreshCredential: $refreshToken, $credentialFormat, $credentialIdentifier")
            val hasScope = credentialFormat.scope != null
            val tokenResponse = postToken(
                oauthMetadata = oauthMetadata,
                issuerMetadata = issuerMetadata,
                tokenRequest = oid4vciService.oauth2Client.createTokenRequestParameters(
                    authorization = AuthorizationForToken.RefreshToken(refreshToken),
                    state = null,
                    scope = credentialFormat.scope,
                    authorizationDetails = if (!hasScope) oid4vciService.buildAuthorizationDetails(
                        credentialIdentifier,
                        issuerMetadata.authorizationServers
                    ) else null
                ),
            )
            Napier.i("Received token response")
            Napier.d("Received token response $tokenResponse")

            val credentialScheme = credentialFormat.resolveCredentialScheme()
                ?: throw Exception("Unknown credential scheme in $credentialFormat")

            postCredentialRequestAndStore(
                issuerMetadata = issuerMetadata,
                tokenResponse = tokenResponse,
                credentialFormat = credentialFormat,
                credentialScheme = credentialScheme,
                oauthMetadata = oauthMetadata,
                credentialIdentifier = credentialIdentifier,
                previouslyRequestedScope = credentialFormat.scope,
            )
        }
    }

    @Throws(Exception::class)
    private suspend fun postToken(
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        issuerMetadata: IssuerMetadata,
        tokenRequest: TokenRequestParameters,
    ): TokenResponseParameters {
        val tokenEndpointUrl = oauthMetadata.tokenEndpoint
            ?: throw Exception("No tokenEndpoint in $oauthMetadata")
        Napier.i("postToken: $tokenEndpointUrl with $tokenRequest")

        val clientAttestationJwt = if (oauthMetadata.useClientAuth()) {
            loadClientAttestationJwt.invoke()
        } else null
        val clientAttestationPoPJwt = if (oauthMetadata.useClientAuth()) {
            clientAttestationJwsService.buildClientAttestationPoPJwt(
                clientId = oid4vciService.clientId,
                audience = issuerMetadata.credentialIssuer,
                lifetime = 10.minutes,
            ).serialize()
        } else null
        val dpopHeader = if (oauthMetadata.hasMatchingDpopAlgorithm()) {
            dpopJwsService.buildDPoPHeader(url = tokenEndpointUrl)
        } else null

        return client.submitForm(
            url = tokenEndpointUrl,
            formParameters = parameters {
                tokenRequest.encodeToParameters<TokenRequestParameters>().forEach { append(it.key, it.value) }
            }
        ) {
            headers {
                clientAttestationJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttestationPoPJwt?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
                dpopHeader?.let { append(HttpHeaders.DPoP, it) }
            }
        }.body<TokenResponseParameters>()
    }

    private fun OAuth2AuthorizationServerMetadata.useClientAuth(): Boolean =
        tokenEndPointAuthMethodsSupported?.contains(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true

    private fun OAuth2AuthorizationServerMetadata.hasMatchingDpopAlgorithm(): Boolean =
        dpopSigningAlgValuesSupported?.contains(dpopJwsService.algorithm) == true

    /**
     * Will use the [tokenResponse] to request a credential and store it with [storeCredential].
     */
    @Throws(Exception::class)
    private suspend fun postCredentialRequestAndStore(
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseParameters,
        credentialFormat: SupportedCredentialFormat,
        credentialScheme: ConstantIndex.CredentialScheme,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        credentialIdentifier: String,
        previouslyRequestedScope: String?
    ) {
        val credentialEndpointUrl = issuerMetadata.credentialEndpointUrl
        Napier.i("postCredentialRequestAndStore: $credentialEndpointUrl")
        Napier.d("postCredentialRequestAndStore: $tokenResponse")

        val clientNonce = issuerMetadata.nonceEndpointUrl?.let { nonceUrl ->
            client.post(nonceUrl).body<ClientNonceResponse>().clientNonce.also {
                Napier.i("postCredentialRequestAndStore: $it from $nonceUrl")
            }
        }

        val credentialRequests = oid4vciService.createCredentialRequest(
            tokenResponse = tokenResponse,
            metadata = issuerMetadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope
        ).getOrThrow()

        val dpopHeader = if (tokenResponse.tokenType.equals(TOKEN_TYPE_DPOP, true))
            dpopJwsService.buildDPoPHeader(url = credentialEndpointUrl, accessToken = tokenResponse.accessToken)
        else null

        if (tokenResponse.refreshToken != null) {
            storeRefreshToken.invoke(
                RefreshTokenInfo(
                    refreshToken = tokenResponse.refreshToken!!,
                    issuerMetadata = issuerMetadata,
                    oauthMetadata = oauthMetadata,
                    credentialFormat = credentialFormat,
                    credentialIdentifier = credentialIdentifier,
                )
            )
        }

        credentialRequests.forEach { credentialRequest ->
            val credentialResponse: CredentialResponseParameters = client.post(credentialEndpointUrl) {
                contentType(ContentType.Application.Json)
                setBody(credentialRequest)
                headers {
                    append(HttpHeaders.Authorization, tokenResponse.toHttpHeaderValue())
                    dpopHeader?.let { append(HttpHeaders.DPoP, it) }
                }
            }.body()

            credentialResponse.extractCredentials()
                .ifEmpty { throw Exception("No credential was received") }
                .forEach {
                    storeCredential.invoke(
                        it.toStoreCredentialInput(credentialFormat.format.toRepresentation(), credentialScheme)
                    )
                }
        }
    }

    @Deprecated(
        "Removed in OID4VCI draft 15",
        ReplaceWith("loadCredentialWithOffer(credentialOffer, credentialIdentifierInfo, transactionCode)")
    )
    suspend fun loadCredentialWithOffer(
        credentialOffer: CredentialOffer,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        transactionCode: String? = null,
        @Suppress("unused") requestedAttributes: Set<NormalizedJsonPath>?,
    ) = loadCredentialWithOffer(
        credentialOffer = credentialOffer,
        credentialIdentifierInfo = credentialIdentifierInfo,
        transactionCode = transactionCode
    )

    /**
     * Loads a user-selected credential with pre-authorized code from the OID4VCI credential issuer
     *
     * @param credentialOffer as loaded and decoded from the QR Code
     * @param credentialIdentifierInfo as selected by the user from the issuer's metadata
     * @param transactionCode if required from Issuing service, i.e. transmitted out-of-band to the user
     */
    @Throws(Throwable::class)
    suspend fun loadCredentialWithOffer(
        credentialOffer: CredentialOffer,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        transactionCode: String? = null,
    ): KmmResult<Unit> = catching {
        Napier.i("loadCredentialWithOffer: $credentialOffer")
        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull()
            ?: credentialOffer.credentialIssuer
        val oauthMetadata = client
            .get("$authorizationServer${OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION}")
            .body<OAuth2AuthorizationServerMetadata>()
        val state = uuid4().toString()

        credentialOffer.grants?.preAuthorizedCode?.let {
            val credentialScheme = credentialIdentifierInfo.supportedCredentialFormat.resolveCredentialScheme()
                ?: throw Exception("Unknown credential scheme in $credentialIdentifierInfo")

            val hasScope = credentialIdentifierInfo.supportedCredentialFormat.scope != null
            val tokenResponse = postToken(
                oauthMetadata = oauthMetadata,
                issuerMetadata = issuerMetadata,
                tokenRequest = oid4vciService.oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = AuthorizationForToken.PreAuthCode(it.preAuthorizedCode, transactionCode),
                    scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                    authorizationDetails = if (!hasScope) oid4vciService.buildAuthorizationDetails(
                        credentialIdentifierInfo.credentialIdentifier,
                        issuerMetadata.authorizationServers
                    ) else null
                )
            )
            Napier.i("Received token response")
            Napier.d("Received token response: $tokenResponse")

            postCredentialRequestAndStore(
                issuerMetadata = issuerMetadata,
                tokenResponse = tokenResponse,
                credentialFormat = credentialIdentifierInfo.supportedCredentialFormat,
                credentialScheme = credentialScheme,
                oauthMetadata = oauthMetadata,
                credentialIdentifier = credentialIdentifierInfo.credentialIdentifier,
                previouslyRequestedScope = credentialIdentifierInfo.supportedCredentialFormat.scope,
            )
        } ?: credentialOffer.grants?.authorizationCode?.let {
            ProvisioningContext(
                state = state,
                credential = credentialIdentifierInfo,
                oauthMetadata = oauthMetadata,
                issuerMetadata = issuerMetadata
            ).let {
                storeProvisioningContext.invoke(it)
                Napier.d("Store context: $it")
            }

            openAuthRequestInBrowser(
                state = state,
                scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    credentialIdentifierInfo.credentialIdentifier,
                    issuerMetadata.authorizationServers
                ),
                credentialIssuer = credentialOffer.credentialIssuer,
                issuerState = it.issuerState,
                oauthMetadata = oauthMetadata,
            )
        } ?: throw Exception("No offer grants received in ${credentialOffer.grants}")
    }

    @Throws(Exception::class)
    private fun String.toStoreCredentialInput(
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme,
    ): Holder.StoreCredentialInput = when (credentialRepresentation) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> Vc(this, credentialScheme)
        ConstantIndex.CredentialRepresentation.SD_JWT -> SdJwt(this, credentialScheme)
        ConstantIndex.CredentialRepresentation.ISO_MDOC ->
            runCatching { Iso(IssuerSigned.deserialize(decodeToByteArray(Base64())).getOrThrow(), credentialScheme) }
                .getOrElse { throw Exception("Invalid credential format: $this", it) }
    }

    /**
     * Builds the authorization request ([AuthenticationRequestParameters]) to start authentication at the
     * authorization server associated with the credential issuer.
     *
     * Prefers building the authn request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     *
     * Uses Pushed Authorization Requests [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126) if advised
     * by the authorization server.
     *
     * Will call [openUrlExternally] in the end to perform user authentication in a browser.
     *
     * Process continues at [resumeWithAuthCode].
     */
    @Throws(Exception::class)
    private suspend fun openAuthRequestInBrowser(
        state: String,
        scope: String?,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        credentialIssuer: String,
        issuerState: String? = null,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
    ) {
        val authorizationEndpointUrl = oauthMetadata.authorizationEndpoint
            ?: throw Exception("no authorizationEndpoint in $oauthMetadata")
        val authRequest = oid4vciService.oauth2Client.createAuthRequest(
            state = state,
            authorizationDetails = if (scope == null) authorizationDetails else null,
            issuerState = issuerState,
            scope = scope
        )
        val push = oauthMetadata.requirePushedAuthorizationRequests == true
        val parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint
        val authorizationUrl = if (parEndpointUrl != null && push) {
            val authRequestAfterPar = pushAuthorizationRequest(
                authRequest = authRequest,
                state = state,
                url = parEndpointUrl,
                credentialIssuer = credentialIssuer,
                tokenAuthMethods = oauthMetadata.tokenEndPointAuthMethodsSupported
            )
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequestAfterPar.encodeToParameters<AuthenticationRequestParameters>().forEach {
                    builder.parameters.append(it.key, it.value)
                }
            }.build().toString()
        } else {
            URLBuilder(authorizationEndpointUrl).also { builder ->
                authRequest.encodeToParameters<AuthenticationRequestParameters>().forEach {
                    builder.parameters.append(it.key, it.value)
                }
                builder.parameters.append(PARAMETER_PROMPT, PARAMETER_PROMPT_LOGIN)
            }.build().toString()
        }
        Napier.i("Provisioning starts by opening URL $authorizationUrl")
        openUrlExternally.invoke(authorizationUrl)
    }

    @Throws(Exception::class)
    private suspend fun pushAuthorizationRequest(
        authRequest: AuthenticationRequestParameters,
        state: String,
        url: String,
        credentialIssuer: String,
        tokenAuthMethods: Set<String>?,
    ): AuthenticationRequestParameters {
        val shouldIncludeClientAttestation = tokenAuthMethods?.contains(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true
        val clientAttestationJwt = if (shouldIncludeClientAttestation) {
            loadClientAttestationJwt.invoke()
        } else null
        val clientAttestationPoPJwt = if (shouldIncludeClientAttestation) {
            clientAttestationJwsService.buildClientAttestationPoPJwt(
                clientId = oid4vciService.clientId,
                audience = credentialIssuer,
                lifetime = 10.minutes,
            ).serialize()
        } else null
        val response = client.submitForm(
            url = url,
            formParameters = parameters {
                authRequest.encodeToParameters().forEach { append(it.key, it.value) }
                append(PARAMETER_PROMPT, PARAMETER_PROMPT_LOGIN)
            }
        ) {
            headers {
                clientAttestationJwt?.let { append(HttpHeaders.OAuthClientAttestation, it) }
                clientAttestationPoPJwt?.let { append(HttpHeaders.OAuthClientAttestationPop, it) }
            }
        }.body<PushedAuthenticationResponseParameters>()
        if (response.errorDescription != null) {
            throw Exception(response.errorDescription)
        }
        if (response.error != null) {
            throw Exception(response.error)
        }
        if (response.requestUri == null) {
            throw Exception("No request_uri from PAR response at $url")
        }

        return AuthenticationRequestParameters(
            clientId = oid4vciService.clientId,
            requestUri = response.requestUri,
            state = state,
        )
    }

}

/**
 * Gets stored before jumping into the web browser (with the authorization request),
 * so that we can load it back when we resume the issuing process with the auth code
 */
@Serializable
data class ProvisioningContext(
    val state: String,
    val credential: CredentialIdentifierInfo,
    val oauthMetadata: OAuth2AuthorizationServerMetadata,
    val issuerMetadata: IssuerMetadata,
)

/**
 * Gets parsed from the credential issuer's metadata, essentially an entry from
 * [IssuerMetadata.supportedCredentialConfigurations]
 */
@Serializable
data class CredentialIdentifierInfo(
    val issuerMetadata: IssuerMetadata,
    val credentialIdentifier: String,
    val supportedCredentialFormat: SupportedCredentialFormat,
)

/**
 * Holds all information needed to refresh a credential, pass it to [OpenId4VciClient.refreshCredential].
 */
@Serializable
data class RefreshTokenInfo(
    val refreshToken: String,
    val issuerMetadata: IssuerMetadata,
    val oauthMetadata: OAuth2AuthorizationServerMetadata,
    val credentialFormat: SupportedCredentialFormat,
    val credentialIdentifier: String,
)


private val HttpHeaders.OAuthClientAttestation: String
    get() = "OAuth-Client-Attestation"

private val HttpHeaders.OAuthClientAttestationPop: String
    get() = "OAuth-Client-Attestation-PoP"

private val HttpHeaders.DPoP: String
    get() = "DPoP"