package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER
import at.asitplus.openid.OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoMdocFallbackCredentialScheme
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.SdJwtFallbackCredentialScheme
import at.asitplus.wallet.lib.data.VcFallbackCredentialScheme
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.WalletService
import at.asitplus.wallet.lib.oidvci.toRepresentation
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.Serializable


/**
 * Implements the client side of
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 *  Draft 15, 2024-12-19.
 *
 * Supported features:
 *  * Pre-authorized grants
 *  * Authentication code flows
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *  * [OAuth 2.0 Pushed Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9126)
 */
class OpenId4VciClient(
    /** ktor engine to use to make requests to issuing service. */
    engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     */
    cookiesStorage: CookiesStorage? = null,
    /** Additional configuration for building the HTTP client, e.g. callers may enable logging. */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /**
     * Callback to load the client attestation JWT, which may be needed as authentication at the AS, where the
     * `clientId` must match [WalletService.clientId] in [oid4vciService] and the key attested in `cnf` must match
     * the key behind [signClientAttestationPop], see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
     */
    @Deprecated("Configure oAuth2Client instead")
    private val loadClientAttestationJwt: (suspend () -> String)? = null,
    /** Used for authenticating the client at the authorization server with client attestation. */
    @Deprecated("Configure oAuth2Client instead")
    private val signClientAttestationPop: SignJwtFun<JsonWebToken>? = SignJwt(
        EphemeralKeyWithoutCert(),
        JwsHeaderNone()
    ),
    /** Used to calculate DPoP, i.e. the key the access token and refresh token gets bound to.
     * Must match [OAuth2KtorClient.signDpop] in [oauth2Client]. */
    private val signDpop: SignJwtFun<JsonWebToken> = SignJwt(EphemeralKeyWithoutCert(), JwsHeaderCertOrJwk()),
    @Deprecated("Configure oAuth2Client instead")
    private val dpopAlgorithm: JwsAlgorithm = JwsAlgorithm.Signature.ES256,
    /**
     * Implements OID4VCI protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works, `cryptoService` provides proof of possession for credential key material.
     */
    val oid4vciService: WalletService = WalletService(),
    private val oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
        engine = engine,
        cookiesStorage = cookiesStorage,
        httpClientConfig = httpClientConfig,
        loadClientAttestationJwt = loadClientAttestationJwt,
        signClientAttestationPop = signClientAttestationPop,
        signDpop = signDpop,
        dpopAlgorithm = dpopAlgorithm,
        oAuth2Client = oid4vciService.oauth2Client,
    ),
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
        (credentialDefinition?.types?.firstNotNullOfOrNull {
            AttributeIndex.resolveAttributeType(it)
                ?: VcFallbackCredentialScheme(vcType = it)
        }
            ?: sdJwtVcType?.let {
                AttributeIndex.resolveSdJwtAttributeType(it)
                    ?: SdJwtFallbackCredentialScheme(sdJwtType = it)
            }
            ?: docType?.let {
                AttributeIndex.resolveIsoDoctype(it)
                    ?: IsoMdocFallbackCredentialScheme(isoDocType = it)
            })

    /**
     * Starts the issuing process at [credentialIssuerUrl].
     * Clients need to handle the result, i.e. open the URL for user authentication or store the credentials.
     * Clients need to call [resumeWithAuthCode] after getting the authorization code back from the authorization
     * server, e.g. by the Wallet app getting opened (see `redirectUrl` at [oid4vciService]) after the browser being
     * redirecting back from the authorization server.
     *
     * @param credentialIssuerUrl URL of the credential issuer service
     * @param credentialIdentifierInfo credential to request, i.e. picked by user selection
     */
    suspend fun startProvisioningWithAuthRequestReturningResult(
        credentialIssuerUrl: String,
        credentialIdentifierInfo: CredentialIdentifierInfo,
    ): KmmResult<CredentialIssuanceResult.OpenUrlForAuthnRequest> = catching {
        Napier.i("startProvisioningWithAuthRequest: $credentialIssuerUrl with $credentialIdentifierInfo")

        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull()
            ?: credentialIssuerUrl
        val oauthMetadata = catching {
            client.get("$authorizationServer$PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER")
                .body<OAuth2AuthorizationServerMetadata>()
        }.getOrElse {
            client.get("$authorizationServer$PATH_WELL_KNOWN_OPENID_CONFIGURATION")
                .body<OAuth2AuthorizationServerMetadata>()
        }

        oauth2Client.startAuthorization(
            oauthMetadata = oauthMetadata,
            authorizationServer = authorizationServer,
            authorizationDetails = oid4vciService.buildAuthorizationDetails(
                credentialIdentifierInfo.credentialIdentifier,
                issuerMetadata.authorizationServers
            ),
            scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
        ).getOrThrow().let {
            CredentialIssuanceResult.OpenUrlForAuthnRequest(
                url = it.url,
                context = ProvisioningContext(
                    state = it.state,
                    credential = credentialIdentifierInfo,
                    oauthMetadata = oauthMetadata,
                    issuerMetadata = issuerMetadata
                )
            )
        }
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
    suspend fun resumeWithAuthCode(
        url: String,
        context: ProvisioningContext,
    ): KmmResult<CredentialIssuanceResult.Success> = catching {
        Napier.i("resumeWithAuthCode")
        Napier.d("resumeWithAuthCode: $url, $context")

        val tokenResponse = oauth2Client.requestTokenWithAuthCode(
            oauthMetadata = context.oauthMetadata,
            url = url,
            authorizationServer = context.issuerMetadata.credentialIssuer,
            state = context.state,
            scope = context.credential.supportedCredentialFormat.scope,
            authorizationDetails = oid4vciService.buildAuthorizationDetails(
                context.credential.credentialIdentifier,
                context.issuerMetadata.authorizationServers
            )
        ).getOrThrow()

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
     * for the first time, as returned in [CredentialIssuanceResult.Success.refreshToken]).
     *
     * Will request a new access token, and use that token to request the same credential again and store it.
     *
     * Prefers building the token request by using `scope` (from [SupportedCredentialFormat]), as advised in
     * [OpenID4VC HAIP](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html),
     * but falls back to authorization details if needed.
     */
    suspend fun refreshCredentialReturningResult(
        refreshTokenInfo: RefreshTokenInfo,
    ): KmmResult<CredentialIssuanceResult.Success> = catching {
        with(refreshTokenInfo) {
            Napier.i("refreshCredential")
            Napier.d("refreshCredential: $refreshToken, $credentialFormat, $credentialIdentifier")
            val tokenResponse = oauth2Client.requestTokenWithRefreshToken(
                oauthMetadata = oauthMetadata,
                credentialIssuer = issuerMetadata.credentialIssuer,
                refreshToken = refreshToken,
                scope = credentialFormat.scope,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    credentialIdentifier,
                    issuerMetadata.authorizationServers
                )
            ).getOrThrow()
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
        previouslyRequestedScope: String?,
    ): CredentialIssuanceResult.Success {
        val credentialEndpointUrl = issuerMetadata.credentialEndpointUrl
        Napier.i("postCredentialRequestAndStore: $credentialEndpointUrl")
        Napier.d("postCredentialRequestAndStore: $tokenResponse")

        val clientNonce = issuerMetadata.nonceEndpointUrl?.let { nonceUrl ->
            client.post(nonceUrl).body<ClientNonceResponse>().clientNonce.also {
                Napier.i("postCredentialRequestAndStore: $it from $nonceUrl")
            }
        }

        val credentialRequests = oid4vciService.createCredential(
            tokenResponse = tokenResponse,
            metadata = issuerMetadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope
        ).getOrThrow()

        val storeCredentialInputs = credentialRequests.flatMap { credentialRequest ->
            val credentialResponse = client.post(credentialEndpointUrl) {
                when (credentialRequest) {
                    is WalletService.CredentialRequest.Encrypted -> {
                        contentType(ContentType.parse(MediaTypes.Application.JWT))
                        setBody(credentialRequest.request.serialize())
                    }
                    is WalletService.CredentialRequest.Plain -> {
                        contentType(ContentType.Application.Json)
                        setBody(credentialRequest.request)
                    }
                }
                oauth2Client.applyToken(tokenResponse, credentialEndpointUrl, HttpMethod.Post)()
            }.body<CredentialResponseParameters>()
            // TODO handle errors?
            oid4vciService.parseCredentialResponse(
                credentialResponse,
                credentialFormat.format.toRepresentation(),
                credentialScheme
            ).getOrThrow()
        }
        return CredentialIssuanceResult.Success(
            storeCredentialInputs,
            tokenResponse.refreshToken?.let {
                RefreshTokenInfo(
                    refreshToken = tokenResponse.refreshToken!!,
                    issuerMetadata = issuerMetadata,
                    oauthMetadata = oauthMetadata,
                    credentialFormat = credentialFormat,
                    credentialIdentifier = credentialIdentifier,
                )
            })
    }

    /**
     * Loads a user-selected credential with pre-authorized code from the OID4VCI credential issuer
     *
     * @param credentialOffer as loaded and decoded from the QR Code
     * @param credentialIdentifierInfo as selected by the user from the issuer's metadata
     * @param transactionCode if required from Issuing service, i.e. transmitted out-of-band to the user
     */
    suspend fun loadCredentialWithOfferReturningResult(
        credentialOffer: CredentialOffer,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        transactionCode: String? = null,
    ): KmmResult<CredentialIssuanceResult> = catching {
        Napier.i("loadCredentialWithOffer: $credentialOffer")
        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull()
            ?: credentialOffer.credentialIssuer
        val oauthMetadata = catching {
            client.get("$authorizationServer$PATH_WELL_KNOWN_OAUTH_AUTHORIZATION_SERVER")
                .body<OAuth2AuthorizationServerMetadata>()
        }.getOrElse {
            client.get("$authorizationServer$PATH_WELL_KNOWN_OPENID_CONFIGURATION")
                .body<OAuth2AuthorizationServerMetadata>()
        }
        val state = uuid4().toString()

        credentialOffer.grants?.preAuthorizedCode?.let {
            val credentialScheme = credentialIdentifierInfo.supportedCredentialFormat.resolveCredentialScheme()
                ?: throw Exception("Unknown credential scheme in $credentialIdentifierInfo")

            val authorizationDetails = oid4vciService.buildAuthorizationDetails(
                credentialIdentifierInfo.credentialIdentifier,
                issuerMetadata.authorizationServers
            )
            val tokenResponse = oauth2Client.requestTokenWithPreAuthorizedCode(
                oauthMetadata = oauthMetadata,
                authorizationServer = issuerMetadata.credentialIssuer,
                preAuthorizedCode = it.preAuthorizedCode,
                transactionCode = transactionCode,
                scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                authorizationDetails = authorizationDetails
            ).getOrThrow()
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

            oauth2Client.startAuthorization(
                oauthMetadata = oauthMetadata,
                authorizationServer = authorizationServer,
                state = state,
                issuerState = it.issuerState,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    credentialIdentifierInfo.credentialIdentifier,
                    issuerMetadata.authorizationServers
                ),
                scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
            ).getOrThrow().let {
                CredentialIssuanceResult.OpenUrlForAuthnRequest(
                    url = it.url,
                    context = ProvisioningContext(
                        state = it.state,
                        credential = credentialIdentifierInfo,
                        oauthMetadata = oauthMetadata,
                        issuerMetadata = issuerMetadata
                    )
                )
            }
        } ?: throw Exception("No offer grants received in ${credentialOffer.grants}")
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
 * Result of the credential issuance process: Either open an authentication request URL externally (i.e. the browser),
 * or store the received credentials.
 */
sealed interface CredentialIssuanceResult {
    /**
     * Store credentials in [credentials], and optionally the [refreshToken] for a later renewal of those credentials.
     */
    data class Success(
        val credentials: Collection<Holder.StoreCredentialInput>,
        val refreshToken: RefreshTokenInfo? = null,
    ) : CredentialIssuanceResult

    /**
     * Open the [url] in a browser (so the user can authenticate at the AS), and store [context] to use in next call
     * to [at.asitplus.wallet.lib.ktor.openid.OpenId4VciClient.resumeWithAuthCode].
     */
    data class OpenUrlForAuthnRequest(
        val url: String,
        val context: ProvisioningContext,
    ) : CredentialIssuanceResult
}

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

