package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH
import at.asitplus.openid.OpenIdConstants.PARAMETER_PROMPT
import at.asitplus.openid.OpenIdConstants.PARAMETER_PROMPT_LOGIN
import at.asitplus.openid.OpenIdConstants.TOKEN_TYPE_DPOP
import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.oauth2.OAuth2Client.AuthorizationForToken
import at.asitplus.wallet.lib.oidvci.*
import at.asitplus.wallet.lib.oidvci.WalletService.CredentialRequestInput
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlin.time.Duration.Companion.minutes


/**
 * Implements the client side of [OpenID for Verifiable Credential Issuance - draft 14](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 *
 * Supported features:
 *  * Pre-authorized grants
 *  * Authentication code flows
 *  * [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449)
 *  * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 */
class OpenId4VciClient(
    /**
     * Used to continue authentication in a web browser,
     * be sure to call back this service at [resumeWithAuthCode]
     */
    private val openUrlExternally: suspend (String) -> Unit,
    /**
     * ktor engine to use to make requests to issuing service
     */
    engine: HttpClientEngine,
    /**
     * Callers are advised to implement a persistent cookie storage,
     * to keep the session at the issuing service alive after receiving the auth code
     */
    cookiesStorage: CookiesStorage? = null,
    /**
     * Additional configuration for building the HTTP client, e.g. callers may enable logging
     */
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
    /**
     * Store context before jumping to an external browser with [openUrlExternally]
     */
    private val storeProvisioningContext: suspend (ProvisioningContext) -> Unit,
    /**
     * Load context after resuming with auth code in [resumeWithAuthCode]
     */
    private val loadProvisioningContext: suspend () -> ProvisioningContext?,
    /**
     * Callback to load the client attestation JWT, which may be needed as authentication at the AS,
     * where the `clientId` must match [clientId] and the key attested in `cnf` must match [cryptoService]'s key, see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
     */
    private val loadClientAttestationJwt: suspend () -> String,
    private val cryptoService: CryptoService,
    private val holderAgent: HolderAgent,
    redirectUrl: String,
    private val clientId: String,
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
    val oid4vciService = WalletService(
        clientId = clientId,
        cryptoService = cryptoService,
        redirectUrl = redirectUrl
    )
    private val jwsService = DefaultJwsService(cryptoService)

    /**
     * Loads credential metadata info from [host]
     */
    suspend fun loadCredentialMetadata(
        host: String,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        Napier.i("loadCredentialMetadata: $host")
        val credentialMetadata = client
            .get("$host${OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER}")
            .body<IssuerMetadata>()
        val supported = credentialMetadata.supportedCredentialConfigurations
            ?: throw Exception("No supported credential configurations")
        supported.mapNotNull {
            CredentialIdentifierInfo(
                credentialIdentifier = it.key,
                attributes = it.value.resolveAttributes()
                    ?: listOf(),
                supportedCredentialFormat = it.value
            )
        }
    }

    private fun SupportedCredentialFormat.resolveAttributes(): Collection<String>? =
        (credentialDefinition?.credentialSubject?.keys
            ?: sdJwtClaims?.keys
            ?: isoClaims?.flatMap { it.value.keys })

    private fun SupportedCredentialFormat.resolveCredentialScheme(): ConstantIndex.CredentialScheme? =
        (credentialDefinition?.types?.firstNotNullOfOrNull { AttributeIndex.resolveAttributeType(it) }
            ?: sdJwtVcType?.let { AttributeIndex.resolveSdJwtAttributeType(it) }
            ?: docType?.let { AttributeIndex.resolveIsoDoctype(it) })

    /**
     * Starts the issuing process at [credentialIssuer]
     */
    suspend fun startProvisioningWithAuthRequest(
        credentialIssuer: String,
        credentialIdentifierInfo: CredentialIdentifierInfo,
        requestedAttributes: Set<NormalizedJsonPath>?,
    ): KmmResult<Unit> = catching {
        Napier.i("startProvisioningWithAuthRequest: $credentialIssuer with $credentialIdentifierInfo")
        // Load certificate, might trigger biometric prompt?
        CoroutineScope(Dispatchers.Unconfined).launch { cryptoService.keyMaterial.getCertificate() }

        val issuerMetadata = client
            .get("$credentialIssuer${OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER}")
            .body<IssuerMetadata>()
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull() ?: credentialIssuer
        val oauthMetadata = client
            .get("$authorizationServer${OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION}")
            .body<OAuth2AuthorizationServerMetadata>()

        val state = uuid4().toString()
        // for now the attribute name is encoded at the first part
        val requestedAttributeStrings = requestedAttributes
            ?.map { (it.segments.first() as NormalizedJsonPathSegment.NameSegment).memberName }
            ?.toSet()

        ProvisioningContext(
            state = state,
            credential = credentialIdentifierInfo,
            requestedAttributes = requestedAttributeStrings,
            oauthMetadata = oauthMetadata,
            issuerMetadata = issuerMetadata
        ).let {
            storeProvisioningContext.invoke(it)
            Napier.i("Store context: $it")
        }

        openAuthRequestInBrowser(
            state = state,
            authorizationDetails = oid4vciService.buildAuthorizationDetails(
                credentialIdentifierInfo.credentialIdentifier,
                issuerMetadata.authorizationServers
            ),
            authorizationEndpointUrl = oauthMetadata.authorizationEndpoint
                ?: throw Exception("no authorizationEndpoint in $oauthMetadata"),
            parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint,
            credentialIssuer = credentialIssuer,
            push = oauthMetadata.requirePushedAuthorizationRequests ?: false,
            tokenAuthMethods = oauthMetadata.tokenEndPointAuthMethodsSupported
        )
    }


    /**
     * Called after getting the redirect back from ID Austria to the Issuing Service
     */
    @Throws(Exception::class)
    suspend fun resumeWithAuthCode(
        url: String
    ): KmmResult<Unit> = catching {
        Napier.i("resumeWithAuthCode: $url")
        val context = loadProvisioningContext()
            ?: throw Exception("No provisioning context")

        val authnResponse = Url(url).parameters.flattenEntries().toMap()
            .decodeFromUrlQuery<AuthenticationResponseParameters>()
        val code = authnResponse.code
            ?: throw Exception("No authn code in $url")

        val tokenResponse = postToken(
            tokenEndpointUrl = context.oauthMetadata.tokenEndpoint
                ?: throw Exception("No tokenEndpoint in ${context.oauthMetadata}"),
            credentialIssuer = context.issuerMetadata.credentialIssuer,
            tokenRequest = oid4vciService.oauth2Client.createTokenRequestParameters(
                state = context.state,
                authorization = AuthorizationForToken.Code(code),
                scope = context.credential.supportedCredentialFormat.scope,
            ),
            dpopSigningAlgValuesSupported = context.oauthMetadata.dpopSigningAlgValuesSupported,
            tokenAuthMethods = context.oauthMetadata.tokenEndPointAuthMethodsSupported,
        )
        Napier.i("Received token response $tokenResponse")

        val credentialScheme = context.credential.supportedCredentialFormat.resolveCredentialScheme()
            ?: throw Exception("Unknown credential scheme in ${context.credential}")
        postCredentialRequestAndStore(
            credentialEndpointUrl = context.issuerMetadata.credentialEndpointUrl,
            input = tokenResponse.extractCredentialRequestInput(
                credentialIdentifier = context.credential.credentialIdentifier,
                requestedAttributes = context.requestedAttributes,
                supportedCredentialFormat = context.credential.supportedCredentialFormat
            ),
            tokenResponse = tokenResponse,
            credentialScheme = credentialScheme,
            credentialIssuer = context.issuerMetadata.credentialIssuer
        )
    }

    private fun TokenResponseParameters.extractCredentialRequestInput(
        credentialIdentifier: String,
        requestedAttributes: Set<String>?,
        supportedCredentialFormat: SupportedCredentialFormat
    ): CredentialRequestInput =
        authorizationDetails?.filterIsInstance<OpenIdAuthorizationDetails>()?.firstOrNull()?.let {
            if (it.credentialConfigurationId != null)
                CredentialRequestInput.CredentialIdentifier(credentialIdentifier) // TODO What about requested attributes?
            else
                CredentialRequestInput.Format(supportedCredentialFormat, requestedAttributes)
        } ?: CredentialRequestInput.Format(supportedCredentialFormat, requestedAttributes)

    @Throws(Exception::class)
    private suspend fun postToken(
        tokenEndpointUrl: String,
        credentialIssuer: String,
        tokenRequest: TokenRequestParameters,
        dpopSigningAlgValuesSupported: Set<JsonWebAlgorithm>? = null,
        tokenAuthMethods: Set<String>? = null
    ): TokenResponseParameters {
        Napier.i("postToken: $tokenEndpointUrl with $tokenRequest")
        val shouldIncludeClientAttestation = tokenAuthMethods?.contains(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true
        val clientAttestationJwt = if (shouldIncludeClientAttestation) {
            loadClientAttestationJwt.invoke()
        } else null
        val clientAttestationPoPJwt = if (shouldIncludeClientAttestation) {
            jwsService.buildClientAttestationPoPJwt(
                clientId = clientId,
                audience = credentialIssuer,
                lifetime = 10.minutes,
            ).serialize()
        } else null

        val dpopHeader = if (dpopSigningAlgValuesSupported?.contains(jwsService.algorithm) == true) {
            jwsService.buildDPoPHeader(url = tokenEndpointUrl)
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

    @Throws(Exception::class)
    private suspend fun postCredentialRequestAndStore(
        credentialEndpointUrl: String,
        input: CredentialRequestInput,
        tokenResponse: TokenResponseParameters,
        credentialScheme: ConstantIndex.CredentialScheme,
        credentialIssuer: String
    ) {
        Napier.i("postCredentialRequestAndStore: $credentialEndpointUrl with $input")
        val credentialRequest = oid4vciService.createCredentialRequest(
            input = input,
            clientNonce = tokenResponse.clientNonce,
            credentialIssuer = credentialIssuer,
        ).getOrThrow()

        val dpopHeader = if (tokenResponse.tokenType.equals(TOKEN_TYPE_DPOP, true))
            jwsService.buildDPoPHeader(url = credentialEndpointUrl, accessToken = tokenResponse.accessToken)
        else null

        val credentialResponse: CredentialResponseParameters = client.post(credentialEndpointUrl) {
            contentType(ContentType.Application.Json)
            setBody(credentialRequest)
            headers {
                append(HttpHeaders.Authorization, "${tokenResponse.tokenType} ${tokenResponse.accessToken}")
                dpopHeader?.let { append(HttpHeaders.DPoP, it) }
            }
        }.body()

        val storeCredentialInput = credentialResponse.credential
            ?.toStoreCredentialInput(credentialResponse.format, credentialScheme)
            ?: throw Exception("No credential was received")

        holderAgent.storeCredential(storeCredentialInput).getOrThrow()
    }

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
        requestedAttributes: Set<NormalizedJsonPath>?
    ): KmmResult<Unit> = catching {
        Napier.i("loadCredentialWithOffer: $credentialOffer")
        val credentialIssuer = credentialOffer.credentialIssuer
        val issuerMetadata = client
            .get("$credentialIssuer${OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER}")
            .body<IssuerMetadata>()
        val authorizationServer = issuerMetadata.authorizationServers?.firstOrNull() ?: credentialIssuer
        val oauthMetadata = client
            .get("$authorizationServer${OpenIdConstants.PATH_WELL_KNOWN_OPENID_CONFIGURATION}")
            .body<OAuth2AuthorizationServerMetadata>()
        val tokenEndpointUrl = oauthMetadata.tokenEndpoint
            ?: throw Exception("no tokenEndpoint in $oauthMetadata")
        val state = uuid4().toString()
        // for now the attribute name is encoded at the first part
        val requestedAttributeStrings = requestedAttributes
            ?.map { (it.segments.first() as NormalizedJsonPathSegment.NameSegment).memberName }
            ?.toSet()

        credentialOffer.grants?.preAuthorizedCode?.let {
            val credentialScheme = credentialIdentifierInfo.supportedCredentialFormat.resolveCredentialScheme()
                ?: throw Exception("Unknown credential scheme in $credentialIdentifierInfo")

            val authorizationDetails = oid4vciService.buildAuthorizationDetails(
                credentialIdentifierInfo.credentialIdentifier,
                issuerMetadata.authorizationServers
            )

            val tokenResponse = postToken(
                tokenEndpointUrl = tokenEndpointUrl,
                credentialIssuer = issuerMetadata.credentialIssuer,
                tokenRequest = oid4vciService.oauth2Client.createTokenRequestParameters(
                    state = state,
                    authorization = AuthorizationForToken.PreAuthCode(it.preAuthorizedCode, transactionCode),
                    authorizationDetails = authorizationDetails
                ),
                dpopSigningAlgValuesSupported = oauthMetadata.dpopSigningAlgValuesSupported,
                tokenAuthMethods = oauthMetadata.tokenEndPointAuthMethodsSupported
            )
            Napier.i("Received token response $tokenResponse")

            postCredentialRequestAndStore(
                credentialEndpointUrl = issuerMetadata.credentialEndpointUrl,
                input = tokenResponse.extractCredentialRequestInput(
                    credentialIdentifier = credentialIdentifierInfo.credentialIdentifier,
                    requestedAttributes = requestedAttributeStrings,
                    supportedCredentialFormat = credentialIdentifierInfo.supportedCredentialFormat
                ),
                tokenResponse = tokenResponse,
                credentialScheme = credentialScheme,
                credentialIssuer = issuerMetadata.credentialIssuer
            )
        } ?: credentialOffer.grants?.authorizationCode?.let {
            ProvisioningContext(
                state = state,
                credential = credentialIdentifierInfo,
                requestedAttributes = requestedAttributeStrings,
                oauthMetadata = oauthMetadata,
                issuerMetadata = issuerMetadata
            ).let {
                storeProvisioningContext.invoke(it)
                Napier.d("Store context: $it")
            }

            openAuthRequestInBrowser(
                state = state,
                authorizationDetails = oid4vciService.buildAuthorizationDetails(
                    credentialIdentifierInfo.credentialIdentifier,
                    issuerMetadata.authorizationServers
                ),
                authorizationEndpointUrl = oauthMetadata.authorizationEndpoint
                    ?: throw Exception("no authorizationEndpoint in $oauthMetadata"),
                parEndpointUrl = oauthMetadata.pushedAuthorizationRequestEndpoint,
                credentialIssuer = credentialIssuer,
                issuerState = it.issuerState,
                push = oauthMetadata.requirePushedAuthorizationRequests == true,
                tokenAuthMethods = oauthMetadata.tokenEndPointAuthMethodsSupported
            )
        } ?: run {
            throw Exception("No offer grants received in ${credentialOffer.grants}")
        }
    }

    @Throws(Exception::class)
    private fun String.toStoreCredentialInput(
        format: CredentialFormatEnum?,
        credentialScheme: ConstantIndex.CredentialScheme,
    ) = when (format) {
        CredentialFormatEnum.JWT_VC -> Holder.StoreCredentialInput.Vc(this, credentialScheme)

        CredentialFormatEnum.VC_SD_JWT -> Holder.StoreCredentialInput.SdJwt(this, credentialScheme)

        CredentialFormatEnum.MSO_MDOC -> kotlin.runCatching { decodeToByteArray(Base64()) }.getOrNull()
            ?.let { IssuerSigned.deserialize(it) }?.getOrNull()
            ?.let { Holder.StoreCredentialInput.Iso(it, credentialScheme) }
            ?: throw Exception("Invalid credential format: $this")

        else -> {
            if (contains("~")) {
                Holder.StoreCredentialInput.SdJwt(this, credentialScheme)
            } else runCatching { decodeToByteArray(Base64()) }.getOrNull()
                ?.let { IssuerSigned.deserialize(it) }?.getOrNull()
                ?.let { Holder.StoreCredentialInput.Iso(it, credentialScheme) }
                ?: Holder.StoreCredentialInput.Vc(this, credentialScheme)
        }
    }

    @Throws(Exception::class)
    private suspend fun openAuthRequestInBrowser(
        state: String,
        authorizationDetails: Set<OpenIdAuthorizationDetails>,
        authorizationEndpointUrl: String,
        parEndpointUrl: String?,
        credentialIssuer: String,
        issuerState: String? = null,
        push: Boolean = false,
        tokenAuthMethods: Set<String>? = null
    ) {
        val authRequest =
            oid4vciService.oauth2Client.createAuthRequest(state, authorizationDetails, issuerState = issuerState)
        val authorizationUrl = if (parEndpointUrl != null && push) {
            val authRequestAfterPar =
                pushAuthorizationRequest(authRequest, state, parEndpointUrl, credentialIssuer, tokenAuthMethods)
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
        Napier.d("Provisioning starts by opening URL $authorizationUrl")
        openUrlExternally.invoke(authorizationUrl)
    }

    @Throws(Exception::class)
    private suspend fun pushAuthorizationRequest(
        authRequest: AuthenticationRequestParameters,
        state: String,
        url: String,
        credentialIssuer: String,
        tokenAuthMethods: Set<String>?
    ): AuthenticationRequestParameters {
        val shouldIncludeClientAttestation = tokenAuthMethods?.contains(AUTH_METHOD_ATTEST_JWT_CLIENT_AUTH) == true
        val clientAttestationJwt = if (shouldIncludeClientAttestation) {
            loadClientAttestationJwt.invoke()
        } else null
        val clientAttestationPoPJwt = if (shouldIncludeClientAttestation) {
            jwsService.buildClientAttestationPoPJwt(
                clientId = clientId,
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
            clientId = clientId,
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
    val requestedAttributes: Set<String>?,
    val oauthMetadata: OAuth2AuthorizationServerMetadata,
    val issuerMetadata: IssuerMetadata,
)

/**
 * Gets parsed from the credential issuer's metadata
 */
@Serializable
data class CredentialIdentifierInfo(
    val credentialIdentifier: String,
    val attributes: Collection<String>,
    val supportedCredentialFormat: SupportedCredentialFormat,
)


private val HttpHeaders.OAuthClientAttestation: String
    get() = "OAuth-Client-Attestation"

private val HttpHeaders.OAuthClientAttestationPop: String
    get() = "OAuth-Client-Attestation-PoP"

private val HttpHeaders.DPoP: String
    get() = "DPoP"