package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.TokenResponseWithDpopNonce
import at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo
import at.asitplus.wallet.lib.oidvci.OpenId4VciProtocolClient
import at.asitplus.wallet.lib.oidvci.WalletService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cookies.*
import kotlinx.serialization.Serializable


/**
 * Implements the client side of
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16 with ktor, by sending the requests of [OpenId4VciProtocolClient] and
 * [at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient], which implement the protocols, in the order of each flow.
 * Supported features:
 *  * Pre-authorized grants
 *  * Authentication code flows
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
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
     * Implements OID4VCI protocol, `redirectUrl` needs to be registered by the OS for this application, so redirection
     * back from browser works, `cryptoService` provides proof of possession for credential key material.
     */
    private val oid4vciService: WalletService = WalletService(),
    /** Internal OAuth 2.0 client passed on to [oauth2Client] with the `clientId` from [oid4vciService] */
    private val oauth2InternalClient: OAuth2Client = OAuth2Client(clientId = oid4vciService.clientId),
    /** OAuth 2.0 client to use during the protocol run. */
    private val oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
        engine = engine,
        cookiesStorage = cookiesStorage,
        httpClientConfig = httpClientConfig,
        oAuth2Client = oauth2InternalClient,
    ),
) {

    /** Sends the requests of all exchanges, sharing the cookies and DPoP nonces of [oauth2Client]. */
    private val client = oauth2Client.client

    private val oauth2 = oauth2Client.protocolClient

    private val vci = OpenId4VciProtocolClient(oid4vciService = oid4vciService, oauth2Client = oauth2)

    /**
     * Loads credential metadata info from [host], call parseCredentialMetadata to parse it,
     * returns a list of [CredentialIdentifierInfo].
     */
    suspend fun loadCredentialMetadata(
        host: String,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        Napier.i("loadCredentialMetadata: $host")
        val issuerMetadata = client.execute(vci.loadIssuerMetadata(host))
        vci.parseCredentialMetadata(issuerMetadata).also {
            Napier.i("loadCredentialMetadata for $host returns $it")
        }.getOrThrow()
    }

    /**
     * Parses IssuerMetadata and returns a list of [CredentialIdentifierInfo].
     */
    fun parseCredentialMetadata(issuerMetadata: IssuerMetadata): KmmResult<Collection<CredentialIdentifierInfo>> =
        vci.parseCredentialMetadata(issuerMetadata)

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
        reissuingStoreEntryId: Long? = null
    ): KmmResult<CredentialIssuanceResult.OpenUrlForAuthnRequest> = catching {
        Napier.i("startProvisioningWithAuthRequest: $credentialIssuerUrl with $credentialIdentifierInfo")
        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = vci.selectAuthorizationServer(issuerMetadata, credentialIssuerUrl)
        val oauthMetadata = client.execute(oauth2.loadAuthorizationServerMetadata(authorizationServer))

        client.execute(
            oauth2.startAuthorization(
                oauthMetadata = oauthMetadata,
                authorizationServer = authorizationServer,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    credentialIdentifierInfo.credentialIdentifier,
                    issuerMetadata.authorizationServers
                ),
                scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                issuerMetadata = issuerMetadata,
            )
        ).let {
            CredentialIssuanceResult.OpenUrlForAuthnRequest(
                url = it.url,
                context = ProvisioningContext(
                    state = it.state,
                    credential = credentialIdentifierInfo,
                    oauthMetadata = oauthMetadata,
                    issuerMetadata = issuerMetadata,
                    reissuingStoreEntryId = reissuingStoreEntryId
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

        val tokenResponse = client.execute(
            oauth2.requestTokenWithAuthCode(
                oauthMetadata = context.oauthMetadata,
                url = url,
                authorizationServer = context.oauthMetadata.issuer,
                state = context.state,
                scope = context.credential.supportedCredentialFormat.scope,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    context.credential.credentialIdentifier,
                    context.issuerMetadata.authorizationServers
                ),
                issuerMetadata = context.issuerMetadata,
            )
        )

        val credentialScheme = vci.resolveCredentialScheme(context.credential.supportedCredentialFormat)
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
        refreshTokenInfo: CredentialRenewalInfo,
    ): KmmResult<CredentialIssuanceResult.Success> = catching {
        with(refreshTokenInfo) {
            Napier.i("refreshCredential")
            Napier.d("refreshCredential: $refreshToken, $credentialFormat, $credentialIdentifier")
            val tokenResponse = client.execute(
                oauth2.requestTokenWithRefreshToken(
                    oauthMetadata = oauthMetadata,
                    credentialIssuer = issuerMetadata.credentialIssuer,
                    refreshToken = refreshToken
                        ?: throw IllegalArgumentException("Refresh token is missing in RefreshTokenInfo"),
                    scope = credentialFormat.scope,
                    authorizationDetails = oid4vciService.buildAuthorizationDetails(
                        credentialIdentifier,
                        issuerMetadata.authorizationServers
                    ),
                    issuerMetadata = issuerMetadata,
                )
            )

            val credentialScheme = vci.resolveCredentialScheme(credentialFormat)
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
     * Will use the [tokenResponse] to request a credential and store it with
     * [at.asitplus.wallet.lib.agent.HolderAgent.storeCredential]
     */
    @Throws(Exception::class)
    private suspend fun postCredentialRequestAndStore(
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseWithDpopNonce,
        credentialFormat: SupportedCredentialFormat,
        credentialScheme: CredentialScheme,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        credentialIdentifier: String,
        previouslyRequestedScope: String?,
    ): CredentialIssuanceResult.Success {
        Napier.i("postCredentialRequestAndStore: ${issuerMetadata.credentialEndpointUrl}")
        Napier.d("postCredentialRequestAndStore: $tokenResponse")

        val clientNonce = vci.nonceRequest(issuerMetadata)?.let { client.execute(it) }
            .also { Napier.i("postCredentialRequestAndStore: uses nonce $it") }

        val requests = oid4vciService.createCredential(
            tokenResponse = tokenResponse.params,
            metadata = issuerMetadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope
        ).getOrThrow()

        val storeCredentialInputs = requests.flatMap {
            client.execute(
                vci.credentialRequest(
                    request = it,
                    issuerMetadata = issuerMetadata,
                    tokenResponse = tokenResponse.params,
                    credentialFormat = credentialFormat,
                    credentialScheme = credentialScheme,
                )
            )
        }
        return CredentialIssuanceResult.Success(
            storeCredentialInputs,
            CredentialRenewalInfo(
                refreshToken = tokenResponse.params.refreshToken,
                issuerMetadata = issuerMetadata,
                oauthMetadata = oauthMetadata,
                credentialFormat = credentialFormat,
                credentialIdentifier = credentialIdentifier,
            )
        )
    }

    /**
     * Loads a user-selected credential with pre-authorized code from the OID4VCI credential issuer
     *
     * @param credentialOffer as loaded and decoded from the QR Code
     * @param credentialIdentifierInfo as selected by the user from the issuer's metadata
     * @param transactionCode if required from Issuing service, i.e. transmitted out-of-band to the user
     * @param authorizationServerMetadata oauthMetadata optionally transmitted via the DC API. Set to null for other flows as it will be fetched from the authorizationServer/credentialIssuer.
     */
    suspend fun loadCredentialWithOfferReturningResult(
        credentialOffer: CredentialOffer,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        transactionCode: String? = null,
        authorizationServerMetadata: OAuth2AuthorizationServerMetadata? = null
    ): KmmResult<CredentialIssuanceResult> = catching {
        Napier.i("loadCredentialWithOffer: $credentialOffer")
        val issuerMetadata = credentialIdentifierInfo.issuerMetadata
        val authorizationServer = vci.selectAuthorizationServer(issuerMetadata, credentialOffer.credentialIssuer)
        val oauthMetadata = authorizationServerMetadata
            ?: client.execute(oauth2.loadAuthorizationServerMetadata(authorizationServer))
        val state = uuid4().toString()
        val preAuthorizedCode = credentialOffer.grants?.preAuthorizedCode
        if (preAuthorizedCode != null) {
            val credentialScheme = vci.resolveCredentialScheme(credentialIdentifierInfo.supportedCredentialFormat)
                ?: throw Exception("Unknown credential scheme in $credentialIdentifierInfo")

            val tokenResponse = client.execute(
                oauth2.requestTokenWithPreAuthorizedCode(
                    oauthMetadata = oauthMetadata,
                    authorizationServer = preAuthorizedCode.authorizationServer ?: issuerMetadata.credentialIssuer,
                    preAuthorizedCode = preAuthorizedCode.preAuthorizedCode,
                    transactionCode = transactionCode,
                    scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                    authorizationDetails = oid4vciService.buildAuthorizationDetails(
                        credentialIdentifierInfo.credentialIdentifier,
                        issuerMetadata.authorizationServers
                    ),
                    issuerMetadata = issuerMetadata,
                )
            )

            postCredentialRequestAndStore(
                issuerMetadata = issuerMetadata,
                tokenResponse = tokenResponse,
                credentialFormat = credentialIdentifierInfo.supportedCredentialFormat,
                credentialScheme = credentialScheme,
                oauthMetadata = oauthMetadata,
                credentialIdentifier = credentialIdentifierInfo.credentialIdentifier,
                previouslyRequestedScope = credentialIdentifierInfo.supportedCredentialFormat.scope,
            )
        } else {
            client.execute(
                oauth2.startAuthorization(
                    oauthMetadata = oauthMetadata,
                    authorizationServer = credentialOffer.grants?.authorizationCode?.authorizationServer
                        ?: authorizationServer,
                    state = state,
                    issuerState = credentialOffer.grants?.authorizationCode?.issuerState,
                    authorizationDetails = oid4vciService.buildAuthorizationDetails(
                        credentialIdentifierInfo.credentialIdentifier,
                        issuerMetadata.authorizationServers
                    ),
                    scope = credentialIdentifierInfo.supportedCredentialFormat.scope,
                    issuerMetadata = issuerMetadata,
                )
            ).let {
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
    val reissuingStoreEntryId: Long? = null,
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
        val refreshToken: CredentialRenewalInfo? = null,
    ) : CredentialIssuanceResult

    /**
     * Open the [url] in a browser (so the user can authenticate at the AS), and store [context] to use in next call
     * to [OpenId4VciClient.resumeWithAuthCode].
     */
    data class OpenUrlForAuthnRequest(
        val url: String,
        val context: ProvisioningContext,
    ) : CredentialIssuanceResult
}

@Deprecated(
    "Moved to vck-openid, which does not depend on a ktor client",
    ReplaceWith("CredentialIdentifierInfo", "at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo"),
)
typealias CredentialIdentifierInfo = at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo

