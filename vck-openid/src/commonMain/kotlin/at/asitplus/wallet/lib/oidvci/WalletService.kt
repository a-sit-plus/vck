package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
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
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

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

    val oauth2Client: OAuth2Client = OAuth2Client(clientId, redirectUrl)

    constructor(
        clientId: String = "https://wallet.a-sit.at/app",
        redirectUrl: String = "$clientId/callback",
        keyMaterial: KeyMaterial,
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
        stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
    ) : this(
        clientId = clientId,
        redirectUrl = redirectUrl,
        cryptoService = DefaultCryptoService(keyMaterial),
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
     * Build authorization details for use in [OAuth2Client.createAuthRequest].
     *
     * @param credentialConfigurationId which credentials to request, i.e.
     * one of the keys from [IssuerMetadata.supportedCredentialConfigurations],
     * or from [CredentialOffer.configurationIds]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    fun buildAuthorizationDetails(
        credentialConfigurationId: String,
        authorizationServers: Set<String>? = null,
    ) = buildAuthorizationDetails(setOf(credentialConfigurationId), authorizationServers)

    /**
     * Build authorization details for use in [OAuth2Client.createAuthRequest].
     *
     * @param credentialConfigurationIds which credentials to request, i.e.
     * filtered keys from [IssuerMetadata.supportedCredentialConfigurations],
     * or from [CredentialOffer.configurationIds]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    fun buildAuthorizationDetails(
        credentialConfigurationIds: Set<String>,
        authorizationServers: Set<String>? = null,
    ) = credentialConfigurationIds.map {
        OpenIdAuthorizationDetails(
            credentialConfigurationId = it,
            locations = authorizationServers,
            // Not supporting different credential datasets for one credential configuration at the moment,
            // so we'll just use the `credentialConfigurationId`, see OID4VCI 6.2
            credentialIdentifiers = setOf(it)
        )
    }.toSet()

    /**
     * Build `scope` value for use in [OAuth2Client.createAuthRequest] and [OAuth2Client.createTokenRequestParameters].
     */
    fun buildScope(
        requestOptions: RequestOptions,
        metadata: IssuerMetadata
    ) = metadata.supportedCredentialConfigurations?.values?.filter {
        it.format.toRepresentation() == requestOptions.representation
    }?.firstOrNull {
        when (requestOptions.representation) {
            PLAIN_JWT -> it.credentialDefinition?.types?.contains(requestOptions.credentialScheme.vcType!!) == true
            SD_JWT -> it.sdJwtVcType == requestOptions.credentialScheme.sdJwtType!!
            ISO_MDOC -> it.docType == requestOptions.credentialScheme.isoDocType!!
        }
    }?.scope

    sealed class CredentialRequestInput {
        /**
         * @param id from the token response, see [TokenResponseParameters.authorizationDetails]
         * and [OpenIdcredentialConfigurationId]
         */
        data class CredentialIdentifier(val id: String) : CredentialRequestInput()
        data class RequestOptions(val requestOptions: WalletService.RequestOptions) : CredentialRequestInput()
        data class Format(
            val supportedCredentialFormat: SupportedCredentialFormat,
            val requestedAttributes: Set<String>? = null
        ) : CredentialRequestInput()
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     *
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     *
     * Be sure to include a DPoP header if [TokenResponseParameters.tokenType] is `DPoP`,
     * see [JwsService.buildDPoPHeader].
     *
     * See [OAuth2Client.createTokenRequestParameters].
     *
     * Sample ktor code:
     * ```
     * val token = ...
     * val credentialRequest = client.createCredentialRequest(
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
     * @param input which credential to request, see subclasses of [CredentialRequestInput]
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequest(
        input: CredentialRequestInput,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        val clock = (input as? CredentialRequestInput.RequestOptions)?.requestOptions?.clock ?: Clock.System
        when (input) {
            is CredentialRequestInput.CredentialIdentifier ->
                CredentialRequestParameters(credentialIdentifier = input.id)

            is CredentialRequestInput.Format ->
                input.supportedCredentialFormat.toCredentialRequestParameters(input.requestedAttributes)

            is CredentialRequestInput.RequestOptions -> with(input.requestOptions) {
                credentialScheme.toCredentialRequestParameters(representation, requestedAttributes)
            }
        }.copy(
            proof = createCredentialRequestProof(clientNonce, credentialIssuer, clock)
        ).also { Napier.i("createCredentialRequest returns $it") }
    }


    internal suspend fun createCredentialRequestProof(
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock = Clock.System,
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
                issuedAt = clock.now(),
                nonce = clientNonce,
            ),
            serializer = JsonWebToken.serializer(),
            addKeyId = false,
            addJsonWebKey = true,
            addX5c = false,
        ).getOrThrow().serialize()
    )

    private fun ConstantIndex.CredentialScheme.toCredentialRequestParameters(
        credentialRepresentation: CredentialRepresentation,
        requestedAttributes: Set<String>?,
    ) = when {
        credentialRepresentation == PLAIN_JWT && supportsVcJwt -> CredentialRequestParameters(
            format = CredentialFormatEnum.JWT_VC,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = setOf(VERIFIABLE_CREDENTIAL, vcType!!),
            ),
        )

        credentialRepresentation == SD_JWT && supportsSdJwt -> CredentialRequestParameters(
            format = CredentialFormatEnum.VC_SD_JWT,
            sdJwtVcType = sdJwtType!!,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtType!!),
        )

        credentialRepresentation == ISO_MDOC && supportsIso -> CredentialRequestParameters(
            format = CredentialFormatEnum.MSO_MDOC,
            docType = isoDocType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoNamespace!!),
        )

        else -> throw IllegalArgumentException("format $credentialRepresentation not applicable to $this")
    }

    private fun SupportedCredentialFormat.toCredentialRequestParameters(
        requestedAttributes: Set<String>?,
    ) = when (format) {
        CredentialFormatEnum.JWT_VC -> CredentialRequestParameters(
            format = format,
            credentialDefinition = credentialDefinition,
        )

        CredentialFormatEnum.VC_SD_JWT -> CredentialRequestParameters(
            format = format,
            sdJwtVcType = sdJwtVcType,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(sdJwtVcType!!),
        )

        CredentialFormatEnum.MSO_MDOC -> CredentialRequestParameters(
            format = format,
            docType = docType,
            claims = requestedAttributes?.toRequestedClaimsIso(isoClaims?.keys?.firstOrNull() ?: docType!!),
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
    ),
    serializer = JsonWebToken.serializer(),
    addKeyId = false,
    addJsonWebKey = true,
    addX5c = false,
).getOrThrow().serialize()

/**
 * Client attestation JWT, issued by the backend service to a client, which can be sent to an OAuth2 Authorization
 * Server if needed, e.g. as HTTP header `OAuth-Client-Attestation`, see
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *
 * @param clientId OAuth 2.0 client ID of the wallet
 * @param issuer a unique identifier for the entity that issued the JWT
 * @param clientKey key to be attested, i.e. included in a [ConfirmationClaim]
 * @param keyType optional key type acc. to OID4VC HAIP with SD-JWT VC to include in the [ConfirmationClaim]
 * @param userAuthentication optional user authentication acc. to OID4VC HAIP with SD-JWT VC to include in the [ConfirmationClaim]
 * @param lifetime validity period of the assertion (minus the [clockSkew])
 * @param clockSkew duration to subtract from [Clock.System.now] when setting the creation timestamp
 */
suspend fun JwsService.buildClientAttestationJwt(
    clientId: String,
    issuer: String,
    clientKey: JsonWebKey,
    keyType: WalletAttestationKeyType? = null,
    userAuthentication: WalletAttestationUserAuthentication? = null,
    authenticationLevel: String? = null,
    lifetime: Duration = 60.minutes,
    clockSkew: Duration = 5.minutes,
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT
    ),
    payload = JsonWebToken(
        issuer = issuer,
        subject = clientId,
        issuedAt = Clock.System.now() - clockSkew,
        expiration = Clock.System.now() - clockSkew + lifetime,
        authenticationLevel = authenticationLevel,
        confirmationClaim = ConfirmationClaim(
            jsonWebKey = clientKey,
            keyType = keyType,
            userAuthentication = userAuthentication,
        )
    ),
    serializer = JsonWebToken.serializer(),
    addKeyId = false,
    addJsonWebKey = false,
    addX5c = false,
).getOrThrow()

/**
 * Client attestation PoP JWT, issued by the client, which can be sent to an OAuth2 Authorization Server if needed,
 * e.g. as HTTP header `OAuth-Client-Attestation-PoP`, see
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *
 * @param clientId OAuth 2.0 client ID of the wallet
 * @param audience The RFC8414 issuer identifier URL of the authorization server MUST be used
 * @param nonce optionally provided from the authorization server
 * @param lifetime validity period of the assertion (minus the [clockSkew])
 * @param clockSkew duration to subtract from [Clock.System.now] when setting the creation timestamp
 */
suspend fun JwsService.buildClientAttestationPoPJwt(
    clientId: String,
    audience: String,
    nonce: String? = null,
    lifetime: Duration = 10.minutes,
    clockSkew: Duration = 5.minutes
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT
    ),
    payload = JsonWebToken(
        issuer = clientId,
        audience = audience,
        jwtId = Random.nextBytes(12).encodeToString(Base64UrlStrict),
        nonce = nonce,
        issuedAt = Clock.System.now() - clockSkew,
        expiration = Clock.System.now() - clockSkew + lifetime,
    ),
    serializer = JsonWebToken.serializer(),
    addKeyId = false,
    addJsonWebKey = false,
    addX5c = false,
).getOrThrow()
