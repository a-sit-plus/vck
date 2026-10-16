package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferUrlParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdConstants.WellKnownPaths
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwtJsonLd
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.oauth2.LazyExchange
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient
import at.asitplus.wallet.lib.oauth2.OAuth2Utils.insertWellKnownPath
import at.asitplus.wallet.lib.oauth2.PlainExchange
import at.asitplus.wallet.lib.oauth2.ValueExchange
import at.asitplus.wallet.lib.validation.IssuerMetadataValidation
import at.asitplus.wallet.lib.validation.IssuerMetadataValidator
import at.asitplus.wallet.lib.validation.ValidatedCredentialIssuer
import at.asitplus.wallet.lib.validation.ValidationPolicy
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock

/**
 * Implements the client side of
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16, without sending any HTTP request itself: every call returns an [HttpExchange], whose requests
 * the caller sends with any HTTP stack. The KDoc of each method lists the [ProtocolRequest]s its exchange sends.
 *
 * The caller runs the exchanges of a flow in order, using [oauth2Client] for the authorization server, and
 * [vciClient] for the credential requests:
 *
 *  * Credential offer, if any: [loadCredentialOffer], then the pre-authorized code or authorization code flow for it.
 *  * Pre-authorized code: [loadIssuerMetadata], [parseCredentialMetadata], [OAuth2ProtocolClient.loadAuthorizationServerMetadata]
 *    of [selectAuthorizationServer], [OAuth2ProtocolClient.requestTokenWithPreAuthorizedCode], [nonceRequest],
 *    [createCredential], and [credentialRequest] for each of those credential requests.
 *  * Authorization code: the same, but with [OAuth2ProtocolClient.startAuthorization], opening its URL in the browser,
 *    and [OAuth2ProtocolClient.requestTokenWithAuthCode] with the redirect back to the wallet, instead of the
 *    pre-authorized token request.
 *  * Refreshing a credential: [OAuth2ProtocolClient.requestTokenWithRefreshToken], [nonceRequest],
 *    [createCredential], and [credentialRequest].
 *
 * DPoP proofs and nonces for the credential issuer are handled by [oauth2Client].
 */
class OpenId4VciProtocolClient @JvmOverloads constructor(
    /**
     * Implements OID4VCI protocol, i.e. creates credential requests with proofs of possession for the credential key
     * material, and parses the credential responses.
     */
    val vciClient: OpenId4VciClient = OpenId4VciClient(),
    /** Implements OAuth 2.0 with the authorization server, and authenticates requests to the credential issuer. */
    val oauth2Client: OAuth2ProtocolClient = OAuth2ProtocolClient(oAuth2Client = OAuth2Client()),
    /**
     * Validates signed issuer metadata, see [loadIssuerMetadata]: configure it with the anchors of the WRPAC
     * providers, and of the WRPRC providers.
     */
    private val issuerMetadataValidator: IssuerMetadataValidator = IssuerMetadataValidator(),
) {

    /**
     * Loads the [CredentialOffer] from [input], which is either a JSON-encoded credential offer, or a credential offer
     * URL with an embedded `credential_offer` (by value) or a `credential_offer_uri` (by reference).
     * The resource at `credential_offer_uri` is the JSON-encoded credential offer, see [CredentialOfferUrlParameters];
     * another credential offer URL in its place is rejected.
     *
     * Sends no request for a credential offer passed by value, and `CredentialOffer` for one passed by reference.
     */
    fun loadCredentialOffer(
        input: String
    ): HttpExchange<CredentialOffer> = LazyExchange {
        when (val parsed = vciClient.parseCredentialOfferInput(input)) {
            is OpenId4VciClient.CredentialOfferInput.ByValue -> ValueExchange(parsed.offer)
            is OpenId4VciClient.CredentialOfferInput.ByReference -> PlainExchange(
                candidates = listOf(
                    ProtocolRequest.CredentialOffer(PreparedHttpRequest(url = parsed.uri, method = HttpMethod.Get))
                ),
                parse = { with(vciClient) { it.body.decodeCredentialOffer() } },
            )
        }
    }

    /**
     * Loads the unsigned [IssuerMetadata] from [credentialIssuer], see [WellKnownPaths.CredentialIssuer], asking for
     * `application/json` (OpenID4VCI 1.0, 12.2.2). Fails if their `credential_issuer` is not [credentialIssuer]
     * (12.2.4). To load signed metadata, see the overload with a policy.
     *
     * Sends `CredentialIssuerMetadata`.
     */
    fun loadIssuerMetadata(
        credentialIssuer: String,
    ): HttpExchange<IssuerMetadata> = PlainExchange(
        candidates = listOf(issuerMetadataRequest(credentialIssuer, accept = MediaTypes.Application.JSON)),
        parse = { it.body.decodeUnsignedIssuerMetadata(credentialIssuer) },
    )

    /**
     * Loads the metadata of [credentialIssuer], see [WellKnownPaths.CredentialIssuer], asking for signed metadata
     * (`application/jwt`) over unsigned ones (`application/json`), which the credential issuer has to support
     * (OpenID4VCI 1.0, 12.2.2). Takes the media type of the response from its `Content-Type`:
     *  - signed metadata are validated with [issuerMetadataValidator] under [policy], see
     *    [IssuerMetadataValidator.validate], and returned with their report, also if they are rejected, so that the
     *    wallet can show why, e.g. that the access certificate of the credential issuer is not trusted;
     *  - unsigned metadata are returned if their `credential_issuer` is [credentialIssuer] (12.2.4), and it is up to
     *    the wallet whether to use them: e.g. the EUDI Wallet ecosystem requires signed metadata (ETSI TS 119 472-3
     *    V1.1.1, ISS-MDATA-4.2.1-01).
     *
     * Sends `CredentialIssuerMetadata`.
     */
    fun loadIssuerMetadata(
        credentialIssuer: String,
        policy: ValidationPolicy,
    ): HttpExchange<LoadedIssuerMetadata> = PlainExchange(
        candidates = listOf(issuerMetadataRequest(credentialIssuer, accept = ACCEPT_SIGNED_METADATA)),
        parse = { response ->
            val contentType = response.headers[HttpHeaders.ContentType]?.let { ContentType.parse(it) }
                ?: throw IllegalArgumentException("The response indicates no media type of the metadata")
            when {
                contentType.match(MediaTypes.Application.JWT) -> LoadedIssuerMetadata.Signed(
                    issuerMetadataValidator.validate(response.body, credentialIssuer, policy)
                )

                contentType.match(ContentType.Application.Json) -> LoadedIssuerMetadata.Unsigned(
                    response.body.decodeUnsignedIssuerMetadata(credentialIssuer)
                )

                else -> throw IllegalArgumentException("Unsupported media type of the metadata: $contentType")
            }
        },
    )

    private fun issuerMetadataRequest(credentialIssuer: String, accept: String) =
        ProtocolRequest.CredentialIssuerMetadata(
            http = PreparedHttpRequest(
                url = insertWellKnownPath(credentialIssuer, WellKnownPaths.CredentialIssuer),
                method = HttpMethod.Get,
                headers = headers { append(HttpHeaders.Accept, accept) },
            )
        )

    /**
     * "The value MUST be identical to the Credential Issuer's identifier value into which the well-known URI string
     * was inserted [...] If these values are not identical (when compared using a simple string comparison with no
     * normalization), the data contained in the response MUST NOT be used." (OpenID4VCI 1.0, 12.2.4)
     */
    private fun String.decodeUnsignedIssuerMetadata(credentialIssuer: String): IssuerMetadata =
        joseCompliantSerializer.decodeFromString<IssuerMetadata>(this).also {
            require(it.credentialIssuer == credentialIssuer) {
                "credential_issuer ${it.credentialIssuer} is not the credential issuer $credentialIssuer"
            }
        }

    /**
     * Parses [issuerMetadata] and returns a list of [CredentialIdentifierInfo], with the [issuer] validated from
     * signed metadata, if any.
     */
    @JvmOverloads
    fun parseCredentialMetadata(
        issuerMetadata: IssuerMetadata,
        issuer: ValidatedCredentialIssuer? = null,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        issuerMetadata.supportedCredentialConfigurations.map {
            CredentialIdentifierInfo(
                issuerMetadata = issuerMetadata,
                credentialIdentifier = it.key,
                supportedCredentialFormat = it.value,
                issuer = issuer,
            )
        }.also {
            Napier.i("parseCredentialMetadata returns $it")
        }
    }

    /**
     * Parses the metadata of [loaded] and returns a list of [CredentialIdentifierInfo], each with the credential issuer
     * validated from signed metadata, see [LoadedIssuerMetadata.Signed]. Fails for signed metadata that have been
     * rejected, see their report.
     */
    fun parseCredentialMetadata(
        loaded: LoadedIssuerMetadata,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        val metadata = loaded.metadata
            ?: throw IllegalArgumentException("The signed metadata have been rejected, see their report")
        val issuer = (loaded as? LoadedIssuerMetadata.Signed)?.validation?.issuer
        parseCredentialMetadata(metadata, issuer).getOrThrow()
    }

    /**
     * Parses the metadata of [loaded] like [parseCredentialMetadata], but also for signed metadata that have been
     * rejected, e.g. as their signer is not trusted, using [LoadedIssuerMetadata.Signed.untrustedMetadata] without a
     * validated credential issuer. Such metadata are no more trustworthy than unsigned ones: use this only to continue
     * after showing the report to the user. Fails for signed metadata whose signature or subject did not pass.
     */
    fun parseCredentialMetadataIgnoringTrust(
        loaded: LoadedIssuerMetadata,
    ): KmmResult<Collection<CredentialIdentifierInfo>> = catching {
        when (loaded) {
            is LoadedIssuerMetadata.Unsigned -> parseCredentialMetadata(loaded.metadata).getOrThrow()
            is LoadedIssuerMetadata.Signed -> if (loaded.metadata != null) {
                parseCredentialMetadata(loaded).getOrThrow()
            } else {
                val metadata = loaded.untrustedMetadata ?: throw IllegalArgumentException(
                    "The signed metadata are not authenticated for the credential issuer, see their report"
                )
                parseCredentialMetadata(metadata).getOrThrow()
            }
        }
    }

    /**
     * The authorization server to use for [issuerMetadata], i.e. the first entry of
     * [IssuerMetadata.authorizationServers], or [credentialIssuer] itself.
     */
    fun selectAuthorizationServer(
        issuerMetadata: IssuerMetadata,
        credentialIssuer: String
    ): String = issuerMetadata.authorizationServers?.firstOrNull()
        ?: credentialIssuer

    /** Resolves the [CredentialScheme] of [credentialFormat] from the registered schemes, see [AttributeIndex]. */
    suspend fun resolveCredentialScheme(
        credentialFormat: SupportedCredentialFormat
    ): CredentialScheme? = when (credentialFormat) {
        is SupportedCredentialFormatIsoMdoc ->
            AttributeIndex.resolveIdentifier(credentialFormat.docType, ISO_MDOC)

        is SupportedCredentialFormatSdJwt ->
            AttributeIndex.resolveIdentifier(credentialFormat.sdJwtVcType, SD_JWT)

        is SupportedCredentialFormatW3cVcJwt ->
            AttributeIndex.resolveIdentifierPlainJwt(credentialFormat.credentialDefinition.types)

        is SupportedCredentialFormatW3cVcJsonLd ->
            AttributeIndex.resolveIdentifierPlainJwt(credentialFormat.credentialDefinition.type)

        is SupportedCredentialFormatW3cVcJwtJsonLd ->
            AttributeIndex.resolveIdentifierPlainJwt(credentialFormat.credentialDefinition.type)
    }

    /**
     * Requests a fresh `c_nonce` from [IssuerMetadata.nonceEndpointUrl], to be used in
     * [createCredential], or `null` if the credential issuer has no nonce endpoint.
     * The `DPoP-Nonce` of the response, if any, is used by [oauth2Client] for the DPoP proofs of the following
     * [credentialRequest]s.
     *
     * Sends `Nonce`.
     */
    fun nonceRequest(
        issuerMetadata: IssuerMetadata
    ): HttpExchange<String>? = issuerMetadata.nonceEndpointUrl?.let { url ->
        PlainExchange(
            candidates = listOf(ProtocolRequest.Nonce(PreparedHttpRequest(url = url, method = HttpMethod.Post))),
            parse = { joseCompliantSerializer.decodeFromString<ClientNonceResponse>(it.body).clientNonce },
            onResponse = { requestUrl, response ->
                oauth2Client.recordResourceServerResponse(requestUrl, response.headers)
            },
        )
    }

    /**
     * Creates the credential requests for [tokenResponse] with [OpenId4VciClient.createCredential], whose proof JWTs
     * name the `client_id` of [oauth2Client] as the issuer, as
     * [OID4VCI 1.0 Appendix F.1](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1)
     * requires. Send each one with [credentialRequest].
     */
    suspend fun createCredential(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<OpenId4VciClient.CredentialRequest>> = vciClient.createCredential(
        tokenResponse = tokenResponse,
        metadata = metadata,
        credentialFormat = credentialFormat,
        clientNonce = clientNonce,
        previouslyRequestedScope = previouslyRequestedScope,
        clock = clock,
        clientId = oauth2Client.oAuth2Client.clientId,
    )

    /**
     * Creates the credential request for exactly one credential with [OpenId4VciClient.createCredential], whose proof
     * JWT names the `client_id` of [oauth2Client] as the issuer. Send it with [credentialRequest].
     */
    suspend fun createCredential(
        metadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientNonce: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<OpenId4VciClient.CredentialRequest> = vciClient.createCredential(
        metadata = metadata,
        credentialConfigurationId = credentialConfigurationId,
        clientNonce = clientNonce,
        clock = clock,
        clientId = oauth2Client.oAuth2Client.clientId,
    )

    /**
     * Sends [request], as created by [createCredential], to the
     * [IssuerMetadata.credentialEndpointUrl] with the access token from [tokenResponse], and parses the (possibly
     * encrypted) response into credentials to store.
     *
     * Sends `Credential{1,2}`, i.e. retries once if the credential issuer asks for a DPoP nonce.
     */
    fun credentialRequest(
        request: OpenId4VciClient.CredentialRequest,
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseParameters,
        credentialFormat: SupportedCredentialFormat,
        credentialScheme: CredentialScheme,
    ): HttpExchange<Collection<Holder.StoreCredentialInput>> = oauth2Client.accessTokenRequest(
        request = when (request) {
            is OpenId4VciClient.CredentialRequest.Encrypted -> PreparedHttpRequest(
                url = issuerMetadata.credentialEndpointUrl,
                method = HttpMethod.Post,
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JWT),
                body = request.request.serialize(),
            )

            is OpenId4VciClient.CredentialRequest.Plain -> PreparedHttpRequest(
                url = issuerMetadata.credentialEndpointUrl,
                method = HttpMethod.Post,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                body = joseCompliantSerializer.encodeToString(request.request),
            )
        },
        tokenResponse = tokenResponse,
        kind = ProtocolRequest::Credential,
        parse = { response ->
            vciClient.parseCredentialResponse(
                response = response.body,
                isEncrypted = response.headers.isJwt(),
                request = request,
                representation = credentialFormat.format.toRepresentation(),
                scheme = credentialScheme,
            ).getOrThrow()
        },
    )

    private fun Headers.isJwt(): Boolean = catchingUnwrapped {
        get(HttpHeaders.ContentType)?.let { ContentType.parse(it) }
            ?.match(ContentType.parse(MediaTypes.Application.JWT)) == true
    }.getOrDefault(false)
}

/**
 * The metadata of a credential issuer, as it serves them (OpenID4VCI 1.0, 12.2.2): signed and validated, or unsigned,
 * see [OpenId4VciProtocolClient.loadIssuerMetadata].
 */
sealed interface LoadedIssuerMetadata {
    /** The metadata to use, `null` for signed metadata that have been rejected, see [Signed.validation]. */
    val metadata: IssuerMetadata?

    /** Signed metadata, with the report of their validation, and the validated credential issuer if accepted. */
    data class Signed(val validation: IssuerMetadataValidation) : LoadedIssuerMetadata {
        override val metadata: IssuerMetadata?
            get() = validation.metadata

        /** The metadata whatever the decision, if signed for the credential issuer, see [IssuerMetadataValidation]. */
        val untrustedMetadata: IssuerMetadata?
            get() = validation.untrustedMetadata
    }

    /** Unsigned metadata, which are not authenticated by the credential issuer. */
    data class Unsigned(override val metadata: IssuerMetadata) : LoadedIssuerMetadata
}

/** Signed metadata preferred over unsigned ones, see [OpenId4VciProtocolClient.loadIssuerMetadata]. */
private const val ACCEPT_SIGNED_METADATA = "${MediaTypes.Application.JWT}, ${MediaTypes.Application.JSON};q=0.9"

/**
 * Gets parsed from the credential issuer's metadata, essentially an entry from
 * [IssuerMetadata.supportedCredentialConfigurations]
 */
@Serializable
data class CredentialIdentifierInfo(
    val issuerMetadata: IssuerMetadata,
    val credentialIdentifier: String,
    val supportedCredentialFormat: SupportedCredentialFormat,
    /**
     * The credential issuer, as validated from its signed metadata, e.g. to show it to the user during the issuance;
     * `null` for unsigned metadata.
     */
    val issuer: ValidatedCredentialIssuer? = null,
)
