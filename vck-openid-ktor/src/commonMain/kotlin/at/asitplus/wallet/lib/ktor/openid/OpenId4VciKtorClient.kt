package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.data.NonEmptyList
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PreparedCredentialStorage
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.oauth2.ClientAttestation
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.TokenResponseWithDpopNonce
import at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo
import at.asitplus.wallet.lib.oidvci.JwtProofCreator
import at.asitplus.wallet.lib.oidvci.LoadedIssuerMetadata
import at.asitplus.wallet.lib.oidvci.OpenId4VciClient
import at.asitplus.wallet.lib.oidvci.OpenId4VciProtocolClient
import at.asitplus.wallet.lib.oidvci.ReceivedCredential
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.ValidationPolicy
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.cookies.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlin.coroutines.cancellation.CancellationException


@Deprecated("Renamed", ReplaceWith("OpenId4VciKtorClient"))
typealias OpenId4VciClient = OpenId4VciKtorClient

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
class OpenId4VciKtorClient private constructor(
    /**
     * Implements OID4VCI protocol, i.e. creates credential requests with proofs of possession for the credential key
     * material, and parses the credential responses.
     */
    private val oid4vciClient: OpenId4VciClient,
    /** OAuth 2.0 client to use during the protocol run, which sends all requests. */
    private val oauth2Client: OAuth2KtorClient,
    /** Validates signed issuer metadata, see [loadIssuerMetadata]. */
    private val issuerMetadataValidator: IssuerMetadataValidator = IssuerMetadataValidator(),
) {

    /**
     * @param httpClient the app's ktor client, i.e. with its engine, cookie storage (advised to be persistent, to keep
     * the session at the issuing service alive after receiving the auth code) and logging. The requests are sent with a
     * copy that does not follow redirects, see [OAuth2KtorClient] for the plugins it must not have.
     * @param oauth2Client implements OAuth 2.0, holding the `client_id` (also the issuer of credential proofs), the
     * `redirectUrl`, which needs to be registered by the OS for this application, so redirection back from browser
     * works, and the state of authorization requests
     * @param vciClient implements OID4VCI protocol, i.e. creates credential requests with proofs of possession for the
     * credential key material, and parses the credential responses
     * @param clientAttestation authenticates the client with
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html),
     * e.g. with a Wallet Instance Attestation (WIA), or `null` to not use it
     * @param dpopKeyMaterial the key material the access tokens and refresh tokens get bound to, by default the key of
     * [clientAttestation], else an ephemeral key, see [OAuth2KtorClient]
     * @param issuerMetadataValidator validates signed issuer metadata, see [loadIssuerMetadata]: configure it with the
     * anchors of the WRPAC providers, and of the WRPRC providers
     */
    constructor(
        httpClient: HttpClient,
        oauth2Client: OAuth2Client,
        vciClient: OpenId4VciClient = OpenId4VciClient(proofCreators = listOf(JwtProofCreator(EphemeralKeyWithoutCert()))),
        clientAttestation: ClientAttestation? = null,
        dpopKeyMaterial: KeyMaterial = clientAttestation?.keyMaterial ?: EphemeralKeyWithoutCert(),
        issuerMetadataValidator: IssuerMetadataValidator = IssuerMetadataValidator(),
    ) : this(
        oid4vciClient = vciClient,
        oauth2Client = OAuth2KtorClient(
            httpClient = httpClient,
            oAuth2Client = oauth2Client,
            clientAttestation = clientAttestation,
            dpopKeyMaterial = dpopKeyMaterial,
        ),
        issuerMetadataValidator = issuerMetadataValidator,
    )

    /**
     * @param engine ktor engine to use to make requests to issuing service.
     * @param cookiesStorage Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code.
     * @param httpClientConfig Additional configuration for building the HTTP client, e.g. callers may enable logging.
     * @param oid4vciClient Implements OID4VCI protocol, `cryptoService` provides proof of possession for credential
     * key material.
     * @param oauth2InternalClient Internal OAuth 2.0 client passed on to [oauth2Client], with the (deprecated)
     * `clientId` from [oid4vciClient]. The `client_id` of the OAuth 2.0 client in [oauth2Client] is the issuer of
     * credential proofs.
     * @param oauth2Client OAuth 2.0 client to use during the protocol run.
     */
    @Deprecated(
        "Pass the app's HttpClient instead of engine, cookiesStorage and httpClientConfig, the OAuth2Client, which " +
                "holds the client ID for credential proofs too, and the client attestation as ClientAttestation"
    )
    @Suppress("DEPRECATION") // in the default values
    constructor(
        engine: HttpClientEngine,
        cookiesStorage: CookiesStorage? = null,
        httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
        oid4vciClient: OpenId4VciClient = OpenId4VciClient(),
        oauth2InternalClient: OAuth2Client = OAuth2Client(clientId = oid4vciClient.clientId),
        oauth2Client: OAuth2KtorClient = OAuth2KtorClient(
            engine = engine,
            cookiesStorage = cookiesStorage,
            httpClientConfig = httpClientConfig,
            oAuth2Client = oauth2InternalClient,
        ),
    ) : this(oid4vciClient = oid4vciClient, oauth2Client = oauth2Client)

    /** Shares the DPoP nonces of [oauth2Client], which sends all requests. */
    private val vci = OpenId4VciProtocolClient(
        vciClient = oid4vciClient,
        oauth2Client = oauth2Client.protocolClient,
        issuerMetadataValidator = issuerMetadataValidator,
    )

    /**
     * Loads the [CredentialOffer] from [input], i.e. the content of a QR code or deep link: a JSON-encoded credential
     * offer, or a credential offer URL with the offer embedded (`credential_offer`) or passed by reference
     * (`credential_offer_uri`), which will be loaded from the credential issuer.
     */
    suspend fun loadCredentialOffer(
        input: String,
    ): KmmResult<CredentialOffer> = catching {
        oauth2Client.execute(vci.loadCredentialOffer(input))
    }

    /**
     * Loads credential metadata info from [host], call parseCredentialMetadata to parse it,
     * returns a list of [CredentialIdentifierInfo].
     */
    suspend fun loadCredentialMetadata(
        host: String,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        Napier.i("loadCredentialMetadata: $host")
        val issuerMetadata = oauth2Client.execute(vci.loadIssuerMetadata(host))
        vci.parseCredentialMetadata(issuerMetadata).also {
            Napier.i("loadCredentialMetadata for $host returns $it")
        }.getOrThrow()
    }

    /**
     * Loads the metadata of [credentialIssuer], preferring signed metadata, which are validated under [policy], see
     * [OpenId4VciProtocolClient.loadIssuerMetadata]. Pass them to [parseCredentialMetadata], if the wallet accepts
     * them, so that every [CredentialIdentifierInfo] carries the validated credential issuer.
     */
    suspend fun loadIssuerMetadata(
        credentialIssuer: String,
        policy: ValidationPolicy,
    ): KmmResult<LoadedIssuerMetadata> = catching {
        oauth2Client.execute(vci.loadIssuerMetadata(credentialIssuer, policy))
    }

    /**
     * Parses IssuerMetadata and returns a list of [CredentialIdentifierInfo].
     */
    fun parseCredentialMetadata(
        issuerMetadata: IssuerMetadata
    ): KmmResult<Collection<CredentialIdentifierInfo>> = vci.parseCredentialMetadata(issuerMetadata)

    /**
     * Parses the metadata of [loaded], see [loadIssuerMetadata], and returns a list of [CredentialIdentifierInfo], each
     * with the credential issuer validated from signed metadata. Fails for signed metadata that have been rejected.
     */
    fun parseCredentialMetadata(
        loaded: LoadedIssuerMetadata,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = vci.parseCredentialMetadata(loaded)

    /**
     * Parses the metadata of [loaded] also if signed metadata have been rejected, without a validated credential
     * issuer, see [OpenId4VciProtocolClient.parseCredentialMetadataIgnoringTrust]: only to continue after showing the
     * report to the user.
     */
    fun parseCredentialMetadataIgnoringTrust(
        loaded: LoadedIssuerMetadata,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = vci.parseCredentialMetadataIgnoringTrust(loaded)

    /**
     * Starts the issuing process at [credentialIssuerUrl].
     * Clients need to handle the result, i.e. open the URL for user authentication or store the credentials, see
     * [CredentialIssuanceResult.Success.prepareCredentialStorage].
     * Clients need to call [resumeWithAuthCode] after getting the authorization code back from the authorization
     * server, e.g. by the Wallet app getting opened (see `redirectUrl` at [oid4vciClient]) after the browser being
     * redirecting back from the authorization server.
     *
     * @param credentialIssuerUrl URL of the credential issuer service
     * @param credentialIdentifierInfo credential to request, i.e. picked by user selection
     * @param reissuingStoreEntryId the stored credential the new one replaces, if any, kept in the [ProvisioningContext]
     * and returned in [CredentialIssuanceResult.Success.reissuingStoreEntryId]
     */
    suspend fun startProvisioningWithAuthRequestReturningResult(
        credentialIssuerUrl: String,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        reissuingStoreEntryId: Long? = null
    ): KmmResult<CredentialIssuanceResult.OpenUrlForAuthnRequest> = startProvisioningWithAuthRequestReturningResult(
        credentialIssuerUrl = credentialIssuerUrl,
        credentialIdentifierInfos = listOf(credentialIdentifierInfo).toNonEmptyList(),
        reissuingStoreEntryId = reissuingStoreEntryId,
    )

    /**
     * Starts the issuing process at [credentialIssuerUrl] for all of [credentialIdentifierInfos] with one
     * authorization, like the overload for one credential, so that the user authenticates only once.
     *
     * @param credentialIssuerUrl URL of the credential issuer service
     * @param credentialIdentifierInfos credentials to request, i.e. picked by user selection, all of the same
     * credential issuer
     * @param reissuingStoreEntryId the stored credential the new ones replace, if any, kept in the
     * [ProvisioningContext] and returned in [CredentialIssuanceResult.Success.reissuingStoreEntryId]
     */
    suspend fun startProvisioningWithAuthRequestReturningResult(
        credentialIssuerUrl: String,
        credentialIdentifierInfos: NonEmptyList<CredentialIdentifierInfo>,
        reissuingStoreEntryId: Long? = null
    ): KmmResult<CredentialIssuanceResult.OpenUrlForAuthnRequest> = catching {
        Napier.i("startProvisioningWithAuthRequest: $credentialIssuerUrl with $credentialIdentifierInfos")
        val issuerMetadata = credentialIdentifierInfos.first().issuerMetadata
        val authorizationServer = vci.selectAuthorizationServer(issuerMetadata, credentialIssuerUrl)
        val oauthMetadata = oauth2Client.loadAuthorizationServerMetadata(authorizationServer)

        oauth2Client.startAuthorization(
            oauthMetadata = oauthMetadata,
            authorizationServer = authorizationServer,
            authorizationDetails = credentialIdentifierInfos.authorizationDetails(issuerMetadata),
            scope = credentialIdentifierInfos.scope(),
            issuerMetadata = issuerMetadata,
        ).getOrThrow().let {
            CredentialIssuanceResult.OpenUrlForAuthnRequest(
                url = it.url,
                context = ProvisioningContext(
                    state = it.state,
                    credential = credentialIdentifierInfos.first(),
                    credentials = credentialIdentifierInfos,
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

        val credentialIdentifierInfos = context.credentials.toNonEmptyList()
        val tokenResponse = oauth2Client.requestTokenWithAuthCode(
            oauthMetadata = context.oauthMetadata,
            url = url,
            authorizationServer = context.oauthMetadata.issuer,
            state = context.state,
            scope = credentialIdentifierInfos.scope(),
            authorizationDetails = credentialIdentifierInfos.authorizationDetails(context.issuerMetadata),
            issuerMetadata = context.issuerMetadata,
        ).getOrThrow()

        postCredentialRequestAndStore(
            issuerMetadata = context.issuerMetadata,
            tokenResponse = tokenResponse,
            credentialIdentifierInfos = credentialIdentifierInfos,
            oauthMetadata = context.oauthMetadata,
            previouslyRequestedScope = credentialIdentifierInfos.scope(),
            reissuingStoreEntryId = context.reissuingStoreEntryId,
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
            val tokenResponse = oauth2Client.requestTokenWithRefreshToken(
                oauthMetadata = oauthMetadata,
                credentialIssuer = issuerMetadata.credentialIssuer,
                refreshToken = refreshToken
                    ?: throw IllegalArgumentException("Refresh token is missing in RefreshTokenInfo"),
                scope = credentialFormat.scope,
                authorizationDetails = oid4vciClient.buildAuthorizationDetails(
                    credentialIdentifier,
                    issuerMetadata.authorizationServers
                ),
                issuerMetadata = issuerMetadata,
            ).getOrThrow()

            postCredentialRequestAndStore(
                issuerMetadata = issuerMetadata,
                tokenResponse = tokenResponse,
                credentialIdentifierInfos = listOf(
                    CredentialIdentifierInfo(issuerMetadata, credentialIdentifier, credentialFormat)
                ).toNonEmptyList(),
                oauthMetadata = oauthMetadata,
                previouslyRequestedScope = credentialFormat.scope,
            )
        }
    }

    /**
     * Uses [tokenResponse] to request every credential of [credentialIdentifierInfos] it grants, for the caller to
     * store them, see [CredentialIssuanceResult.Success.prepareCredentialStorage]: one [IssuedCredentials] per
     * configuration, each with its own renewal info.
     */
    @Throws(Exception::class, CancellationException::class)
    private suspend fun postCredentialRequestAndStore(
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseWithDpopNonce,
        credentialIdentifierInfos: NonEmptyList<CredentialIdentifierInfo>,
        oauthMetadata: OAuth2AuthorizationServerMetadata,
        previouslyRequestedScope: String?,
        reissuingStoreEntryId: Long? = null,
    ): CredentialIssuanceResult.Success {
        Napier.i("postCredentialRequestAndStore: ${issuerMetadata.credentialEndpointUrl}")
        val issued = vci.prepareCredentialRequests(
            metadata = issuerMetadata,
            tokenResponse = tokenResponse.params,
            credentialFormats = credentialIdentifierInfos.map { it.supportedCredentialFormat }.toSet(),
            previouslyRequestedScope = previouslyRequestedScope,
        ).getOrThrow().groupBy { it.credentialConfigurationId }.map { group ->
            val credentialIdentifierInfo = credentialIdentifierInfos
                .firstOrNull { it.credentialIdentifier == group.key }
                ?: CredentialIdentifierInfo(issuerMetadata, group.key, group.value.first().credentialFormat)
            val scheme = vci.resolveCredentialScheme(credentialIdentifierInfo.supportedCredentialFormat)
                ?: throw Exception("Unknown credential scheme in ${credentialIdentifierInfo.supportedCredentialFormat}")
            IssuedCredentials(
                credentialIdentifierInfo = credentialIdentifierInfo,
                receivedCredentials = group.value.flatMap { requestCredential(it, issuerMetadata, tokenResponse) },
                scheme = scheme,
                refreshToken = CredentialRenewalInfo(
                    refreshToken = tokenResponse.params.refreshToken,
                    issuerMetadata = issuerMetadata,
                    oauthMetadata = oauthMetadata,
                    credentialFormat = credentialIdentifierInfo.supportedCredentialFormat,
                    credentialIdentifier = group.key,
                ),
            )
        }
        return CredentialIssuanceResult.Success(
            issued = issued.toNonEmptyList(),
            reissuingStoreEntryId = reissuingStoreEntryId,
        )
    }

    /**
     * Sends the credential request of [preparedRequest] with a fresh `c_nonce`, as the credential issuer may accept
     * each one only once (OpenID4VCI 1.0, 13.8), and once more with a new one if the credential issuer rejects it, see
     * [OpenId4VciProtocolClient.isInvalidNonce].
     *
     * Sends `Nonce` and `Credential{1,2}`, and both again after `invalid_nonce`.
     */
    @Throws(Exception::class, CancellationException::class)
    private suspend fun requestCredential(
        preparedRequest: OpenId4VciClient.PreparedCredentialRequest,
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseWithDpopNonce,
        retryOnInvalidNonce: Boolean = true,
    ): List<ReceivedCredential> {
        val clientNonce = vci.nonceRequest(issuerMetadata)?.let { oauth2Client.execute(it) }
            .also { Napier.i("requestCredential: uses nonce $it") }
        val request = vci.createCredential(
            request = preparedRequest,
            metadata = issuerMetadata,
            clientNonce = clientNonce,
        ).getOrThrow()
        return catchingUnwrapped {
            oauth2Client.execute(
                vci.credentialRequest(
                    request = request,
                    issuerMetadata = issuerMetadata,
                    tokenResponse = tokenResponse.params,
                    credentialFormat = preparedRequest.credentialFormat,
                )
            )
        }.getOrElse {
            if (retryOnInvalidNonce && vci.isInvalidNonce(it))
                requestCredential(preparedRequest, issuerMetadata, tokenResponse, retryOnInvalidNonce = false)
            else throw it
        }
    }

    /**
     * The `scope` for all of these credentials, if every one of them has one, else `null`: a credential without
     * `scope` can only be requested with `authorization_details` (OpenID4VCI 1.0, 12.2.4), see [authorizationDetails].
     */
    private fun Collection<CredentialIdentifierInfo>.scope(): String? =
        mapNotNull { it.supportedCredentialFormat.scope }.takeIf { it.size == size }?.distinct()?.joinToString(" ")

    /** The `authorization_details` for all of these credentials (OpenID4VCI 1.0, 5.1.1). */
    private fun Collection<CredentialIdentifierInfo>.authorizationDetails(issuerMetadata: IssuerMetadata) =
        oid4vciClient.buildAuthorizationDetails(
            map { it.credentialIdentifier }.toSet(),
            issuerMetadata.authorizationServers
        )

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
        loadCredentialWithOfferReturningResult(
            credentialOffer,
            listOf(credentialIdentifierInfo).toNonEmptyList(),
            transactionCode,
            authorizationServerMetadata
        ).getOrThrow()
    }

    /**
     * Loads some user-selected credentials with pre-authorized code from the OID4VCI credential issuer, with one
     * token for all of them, as a pre-authorized code can usually be used only once
     *
     * @param credentialOffer as loaded and decoded from the QR Code
     * @param credentialIdentifierInfos as selected by the user from the issuer's metadata, all of the same credential
     * issuer
     * @param transactionCode if required from Issuing service, i.e. transmitted out-of-band to the user
     * @param authorizationServerMetadata oauthMetadata optionally transmitted via the DC API. Set to null for other flows as it will be fetched from the authorizationServer/credentialIssuer.
     */
    suspend fun loadCredentialWithOfferReturningResult(
        credentialOffer: CredentialOffer,
        credentialIdentifierInfos: NonEmptyList<CredentialIdentifierInfo>,
        transactionCode: String? = null,
        authorizationServerMetadata: OAuth2AuthorizationServerMetadata? = null
    ): KmmResult<CredentialIssuanceResult> = catching {
        Napier.i("loadCredentialWithOffer: $credentialOffer")
        val issuerMetadata = credentialIdentifierInfos.first().issuerMetadata
        val authorizationServer = vci.selectAuthorizationServer(issuerMetadata, credentialOffer.credentialIssuer)
        val oauthMetadata = authorizationServerMetadata
            ?: oauth2Client.loadAuthorizationServerMetadata(authorizationServer)
        val state = uuid4().toString()
        val scope = credentialIdentifierInfos.scope()
        val preAuthorizedCode = credentialOffer.grants?.preAuthorizedCode
        if (preAuthorizedCode != null) {
            val tokenResponse = oauth2Client.requestTokenWithPreAuthorizedCode(
                oauthMetadata = oauthMetadata,
                authorizationServer = preAuthorizedCode.authorizationServer ?: issuerMetadata.credentialIssuer,
                preAuthorizedCode = preAuthorizedCode.preAuthorizedCode,
                transactionCode = transactionCode,
                scope = scope,
                authorizationDetails = credentialIdentifierInfos.authorizationDetails(issuerMetadata),
                issuerMetadata = issuerMetadata,
            ).getOrThrow()

            postCredentialRequestAndStore(
                issuerMetadata = issuerMetadata,
                tokenResponse = tokenResponse,
                credentialIdentifierInfos = credentialIdentifierInfos,
                oauthMetadata = oauthMetadata,
                previouslyRequestedScope = scope,
            )
        } else {
            oauth2Client.startAuthorization(
                oauthMetadata = oauthMetadata,
                authorizationServer = credentialOffer.grants?.authorizationCode?.authorizationServer
                    ?: authorizationServer,
                state = state,
                issuerState = credentialOffer.grants?.authorizationCode?.issuerState,
                authorizationDetails = credentialIdentifierInfos.authorizationDetails(issuerMetadata),
                scope = scope,
                issuerMetadata = issuerMetadata,
            ).getOrThrow().let {
                CredentialIssuanceResult.OpenUrlForAuthnRequest(
                    url = it.url,
                    context = ProvisioningContext(
                        state = it.state,
                        credential = credentialIdentifierInfos.first(),
                        credentials = credentialIdentifierInfos,
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
    /** The first of [credentials], also so that a context stored by an earlier version can still be decoded. */
    val credential: CredentialIdentifierInfo,
    /**
     * The credentials to request with one authorization, only [credential] for a context stored by an earlier version.
     */
    val credentials: List<CredentialIdentifierInfo> = listOf(credential),
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
     * Store the credentials [issued] for each requested credential configuration after validating them with
     * [prepareCredentialStorage], and optionally their [IssuedCredentials.refreshToken] for a later renewal.
     */
    data class Success(
        /** The credentials of each requested credential configuration. */
        val issued: NonEmptyList<IssuedCredentials>,
        /**
         * The stored credential the [issued] credentials replace, as passed to
         * [OpenId4VciKtorClient.startProvisioningWithAuthRequestReturningResult] and kept in the [ProvisioningContext],
         * for the wallet to remove once it stored the new ones.
         */
        val reissuingStoreEntryId: Long? = null,
    ) : CredentialIssuanceResult {

        /** The renewal info of the first of [issued]. */
        @Deprecated(
            "The credentials of several configurations may be issued: use the refreshToken of each of issued",
            ReplaceWith("issued.first().refreshToken"),
        )
        val refreshToken: CredentialRenewalInfo?
            get() = issued.first().refreshToken

        /** The credentials of all [issued] configurations, decoded without validating them. */
        @Deprecated(
            "The credentials have not been validated: prepare their storage with prepareCredentialStorage, which " +
                    "validates them with the HolderAgent",
        )
        val credentials: Collection<Holder.StoreCredentialInput>
            get() = issued.flatMap { group ->
                group.receivedCredentials.map { it.toStoreCredentialInput(group.scheme) }
            }

        /**
         * Validates every credential of [issued] as the type of its [IssuedCredentials.scheme] for storage by [holder]
         * under [policy], with its [IssuedCredentials.refreshToken] for its renewal, see
         * [ReceivedCredential.prepareCredentialStorage], and stores nothing yet. Show the reports to the user, then
         * store each credential with [HolderAgent.storeAccepted], or, if the user accepts a rejected report, e.g. of an
         * untrusted issuer or a credential missing claims its type requires (see [ValidationPolicy.requiredClaims]),
         * with [HolderAgent.storeAfterUserConsent].
         *
         * The credentials of one configuration are of the same issuer and type, so one decision of the user usually
         * covers them. A credential that can not be decoded is reported as rejected, and can never be stored. Fails
         * only if the scheme of a configuration does not support the representation of one of its credentials.
         */
        suspend fun prepareCredentialStorage(
            holder: HolderAgent,
            policy: ValidationPolicy,
        ): KmmResult<List<PreparedCredentialStorage>> = catching {
            issued.flatMap { group ->
                group.receivedCredentials.map {
                    it.prepareCredentialStorage(holder, group.scheme, policy, group.refreshToken).getOrThrow()
                }
            }
        }
    }

    /**
     * Open the [url] in a browser (so the user can authenticate at the AS), and store [context] to use in next call
     * to [OpenId4VciKtorClient.resumeWithAuthCode].
     */
    data class OpenUrlForAuthnRequest(
        val url: String,
        val context: ProvisioningContext,
    ) : CredentialIssuanceResult
}

/**
 * The credentials issued for one requested credential configuration, see [CredentialIssuanceResult.Success.issued].
 */
data class IssuedCredentials(
    /** The requested credential configuration, as selected from the metadata of the credential issuer. */
    val credentialIdentifierInfo: CredentialIdentifierInfo,
    /**
     * The credentials of the credential responses, not validated yet, see
     * [ReceivedCredential.prepareCredentialStorage].
     */
    val receivedCredentials: List<ReceivedCredential>,
    /** The type the [receivedCredentials] have been requested as. */
    val scheme: CredentialScheme,
    /**
     * To renew the [receivedCredentials] later, see [OpenId4VciKtorClient.refreshCredentialReturningResult]. The
     * refresh token is the one of the whole flow, i.e. shared with the other configurations issued with it.
     */
    val refreshToken: CredentialRenewalInfo?,
)

@Deprecated(
    "Moved to vck-openid, which does not depend on a ktor client",
    ReplaceWith("CredentialIdentifierInfo", "at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo"),
)
typealias CredentialIdentifierInfo = at.asitplus.wallet.lib.oidvci.CredentialIdentifierInfo

/** Decodes the credential without validating it, see [CredentialIssuanceResult.Success.credentials]. */
@Throws(Throwable::class)
private fun ReceivedCredential.toStoreCredentialInput(scheme: CredentialScheme): Holder.StoreCredentialInput =
    when (this) {
        is ReceivedCredential.Undecodable -> throw cause
        is ReceivedCredential.Decoded -> when (val input = input) {
            is CredentialValidationInput.VcJwt -> Holder.StoreCredentialInput.Vc(
                signedVcJws = JwsCompactTyped<VerifiableCredentialJws>(input.compact),
                vcJws = input.compact,
                scheme = scheme as VcJwtCredentialScheme,
            )

            is CredentialValidationInput.SdJwtVc -> Holder.StoreCredentialInput.SdJwt(
                signedSdJwtVc = SdJwtSigned.parseCatching(input.compact).getOrThrow(),
                vcSdJwt = input.compact,
                scheme = scheme as SdJwtCredentialScheme,
            )

            is CredentialValidationInput.IsoMdoc -> Holder.StoreCredentialInput.Iso(
                issuerSigned = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(input.issuerSignedCbor),
                scheme = scheme as IsoMdocCredentialScheme,
            )
        }
    }
