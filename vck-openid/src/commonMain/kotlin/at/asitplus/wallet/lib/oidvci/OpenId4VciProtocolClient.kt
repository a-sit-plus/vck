package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.ClientNonceResponse
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
import at.asitplus.wallet.lib.oauth2.OAuth2ProtocolClient
import at.asitplus.wallet.lib.oauth2.OAuth2Utils.insertWellKnownPath
import at.asitplus.wallet.lib.oauth2.PlainExchange
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmOverloads

/**
 * Implements the client side of
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16, without sending any HTTP request itself: every call returns an [HttpExchange], whose requests
 * the caller sends with any HTTP stack. The KDoc of each method lists the [ProtocolRequest]s its exchange sends.
 *
 * The caller runs the exchanges of a flow in order, using [oauth2Client] for the authorization server, and
 * [oid4vciService] for the credential requests:
 *
 *  * Pre-authorized code: [loadIssuerMetadata], [parseCredentialMetadata], [OAuth2ProtocolClient.loadAuthorizationServerMetadata]
 *    of [selectAuthorizationServer], [OAuth2ProtocolClient.requestTokenWithPreAuthorizedCode], [nonceRequest],
 *    [WalletService.createCredential], and [credentialRequest] for each of those credential requests.
 *  * Authorization code: the same, but with [OAuth2ProtocolClient.startAuthorization], opening its URL in the browser,
 *    and [OAuth2ProtocolClient.requestTokenWithAuthCode] with the redirect back to the wallet, instead of the
 *    pre-authorized token request.
 *  * Refreshing a credential: [OAuth2ProtocolClient.requestTokenWithRefreshToken], [nonceRequest],
 *    [WalletService.createCredential], and [credentialRequest].
 *
 * DPoP proofs and nonces for the credential issuer are handled by [oauth2Client].
 */
class OpenId4VciProtocolClient @JvmOverloads constructor(
    /**
     * Implements OID4VCI protocol, i.e. creates credential requests with proofs of possession for the credential key
     * material, and parses the credential responses.
     */
    val oid4vciService: WalletService = WalletService(),
    /** Implements OAuth 2.0 with the authorization server, and authenticates requests to the credential issuer. */
    val oauth2Client: OAuth2ProtocolClient,
) {

    /**
     * Loads [IssuerMetadata] from [credentialIssuer], see [WellKnownPaths.CredentialIssuer].
     *
     * Sends `CredentialIssuerMetadata`.
     */
    fun loadIssuerMetadata(
        credentialIssuer: String,
    ): HttpExchange<IssuerMetadata> = PlainExchange(
        candidates = listOf(
            ProtocolRequest.CredentialIssuerMetadata(
                http = PreparedHttpRequest(
                    url = insertWellKnownPath(credentialIssuer, WellKnownPaths.CredentialIssuer),
                    method = HttpMethod.Get,
                )
            )
        ),
        parse = { joseCompliantSerializer.decodeFromString<IssuerMetadata>(it.body) },
    )

    /**
     * Parses [issuerMetadata] and returns a list of [CredentialIdentifierInfo].
     */
    fun parseCredentialMetadata(issuerMetadata: IssuerMetadata): KmmResult<Collection<CredentialIdentifierInfo>> =
        catching {
            issuerMetadata.supportedCredentialConfigurations.map {
                CredentialIdentifierInfo(
                    issuerMetadata = issuerMetadata,
                    credentialIdentifier = it.key,
                    supportedCredentialFormat = it.value
                )
            }.also {
                Napier.i("parseCredentialMetadata returns $it")
            }
        }

    /**
     * The authorization server to use for [issuerMetadata], i.e. the first entry of
     * [IssuerMetadata.authorizationServers], or [credentialIssuer] itself.
     */
    fun selectAuthorizationServer(issuerMetadata: IssuerMetadata, credentialIssuer: String): String =
        issuerMetadata.authorizationServers?.firstOrNull() ?: credentialIssuer

    /** Resolves the [CredentialScheme] of [credentialFormat] from the registered schemes, see [AttributeIndex]. */
    suspend fun resolveCredentialScheme(credentialFormat: SupportedCredentialFormat): CredentialScheme? =
        when (credentialFormat) {
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
     * [WalletService.createCredential], or `null` if the credential issuer has no nonce endpoint.
     * The `DPoP-Nonce` of the response, if any, is used by [oauth2Client] for the DPoP proofs of the following
     * [credentialRequest]s.
     *
     * Sends `Nonce`.
     */
    fun nonceRequest(issuerMetadata: IssuerMetadata): HttpExchange<String>? =
        issuerMetadata.nonceEndpointUrl?.let { url ->
            PlainExchange(
                candidates = listOf(ProtocolRequest.Nonce(PreparedHttpRequest(url = url, method = HttpMethod.Post))),
                parse = { joseCompliantSerializer.decodeFromString<ClientNonceResponse>(it.body).clientNonce },
                onResponse = { requestUrl, response ->
                    oauth2Client.recordResourceServerResponse(requestUrl, response.headers)
                },
            )
        }

    /**
     * Sends [request], as created by [WalletService.createCredential], to the
     * [IssuerMetadata.credentialEndpointUrl] with the access token from [tokenResponse], and parses the (possibly
     * encrypted) response into credentials to store.
     *
     * Sends `Credential{1,2}`, i.e. retries once if the credential issuer asks for a DPoP nonce.
     */
    fun credentialRequest(
        request: WalletService.CredentialRequest,
        issuerMetadata: IssuerMetadata,
        tokenResponse: TokenResponseParameters,
        credentialFormat: SupportedCredentialFormat,
        credentialScheme: CredentialScheme,
    ): HttpExchange<Collection<Holder.StoreCredentialInput>> = oauth2Client.accessTokenRequest(
        request = when (request) {
            is WalletService.CredentialRequest.Encrypted -> PreparedHttpRequest(
                url = issuerMetadata.credentialEndpointUrl,
                method = HttpMethod.Post,
                headers = headersOf(HttpHeaders.ContentType, MediaTypes.Application.JWT),
                body = request.request.serialize(),
            )

            is WalletService.CredentialRequest.Plain -> PreparedHttpRequest(
                url = issuerMetadata.credentialEndpointUrl,
                method = HttpMethod.Post,
                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                body = joseCompliantSerializer.encodeToString(request.request),
            )
        },
        tokenResponse = tokenResponse,
        kind = ProtocolRequest::Credential,
        parse = { response ->
            oid4vciService.parseCredentialResponse(
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
 * Gets parsed from the credential issuer's metadata, essentially an entry from
 * [IssuerMetadata.supportedCredentialConfigurations]
 */
@Serializable
data class CredentialIdentifierInfo(
    val issuerMetadata: IssuerMetadata,
    val credentialIdentifier: String,
    val supportedCredentialFormat: SupportedCredentialFormat,
)
