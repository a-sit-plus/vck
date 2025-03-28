package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.ProofType
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
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
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.datetime.Clock

/**
 * Client service to retrieve credentials using OID4VCI
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
 */
class WalletService(
    /** Used to create request parameters, e.g. [AuthenticationRequestParameters], typically a URI. */
    val clientId: String = "https://wallet.a-sit.at/app",
    /** Used to create [AuthenticationRequestParameters] and [TokenRequestParameters]. */
    private val redirectUrl: String = "$clientId/callback",
    /** Used to prove possession of the key material to create [CredentialRequestProof], i.e. the holder key. */
    private val cryptoService: CryptoService = DefaultCryptoService(EphemeralKeyWithoutCert()),
    /** Used to prove possession of the key material to create [CredentialRequestProof]. */
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /**
     * Load key attestation to create [CredentialRequestProof], if required by the credential issuer.
     * Once the definition of this format becomes clear in OpenID for Verifiable Credential Issuance,
     * this should probably be moved to [at.asitplus.wallet.lib.agent.CryptoService].
     */
    private val loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsSigned<KeyAttestationJwt>>)? = null,
    /** Whether to request encryption of credentials, if the issuer supports it. */
    private val requestEncryption: Boolean = false,
    /** Optional key material to advertise for credential response encryption, see [requestEncryption]. */
    private val decryptionKeyMaterial: KeyMaterial? = null,
) {

    data class KeyAttestationInput(val clientNonce: String?, val supportedAlgorithms: Collection<String>?)

    private val jweDecryptionService: JwsService? =
        decryptionKeyMaterial?.let { DefaultJwsService(DefaultCryptoService(decryptionKeyMaterial)) }

    val oauth2Client: OAuth2Client = OAuth2Client(clientId, redirectUrl)

    constructor(
        clientId: String = "https://wallet.a-sit.at/app",
        redirectUrl: String = "$clientId/callback",
        keyMaterial: KeyMaterial,
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    ) : this(
        clientId = clientId,
        redirectUrl = redirectUrl,
        cryptoService = DefaultCryptoService(keyMaterial),
        remoteResourceRetriever = remoteResourceRetriever,
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
        @Deprecated("Removed in OID4VCI draft 15")
        val requestedAttributes: Set<String>? = null,
        /**
         * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
         */
        val state: String = uuid4().toString(),
        /**
         * Modify clock for testing specific scenarios
         */
        @Deprecated("Not used in production code")
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
                remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(uri))
                    ?.let { parseCredentialOffer(it).getOrNull() }
            }
        }.getOrNull() ?: catching {
            CredentialOffer.deserialize(input).getOrThrow()
        }.getOrNull() ?: throw InvalidRequest("could not parse credential offer")
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
        )
    }.toSet()

    /**
     * Extract [SupportedCredentialFormat] from [metadata] by filtering according to [requestOptions].
     */
    fun selectSupportedCredentialFormat(
        requestOptions: RequestOptions,
        metadata: IssuerMetadata,
    ) = metadata.supportedCredentialConfigurations?.values?.filter {
        it.format.toRepresentation() == requestOptions.representation
    }?.firstOrNull {
        when (requestOptions.representation) {
            PLAIN_JWT -> it.credentialDefinition?.types?.contains(requestOptions.credentialScheme.vcType!!) == true
            SD_JWT -> it.sdJwtVcType == requestOptions.credentialScheme.sdJwtType!!
            ISO_MDOC -> it.docType == requestOptions.credentialScheme.isoDocType!!
        }
    }

    /**
     * Build `scope` value for use in [OAuth2Client.createAuthRequest] and [OAuth2Client.createTokenRequestParameters].
     */
    @Deprecated(
        "Extract supported credential format, take scope from there",
        ReplaceWith("selectSupportedCredentialFormat(requestOptions, metadata)?.scope")
    )
    fun buildScope(
        requestOptions: RequestOptions,
        metadata: IssuerMetadata,
    ) = metadata.supportedCredentialConfigurations?.values?.filter {
        it.format.toRepresentation() == requestOptions.representation
    }?.firstOrNull {
        when (requestOptions.representation) {
            PLAIN_JWT -> it.credentialDefinition?.types?.contains(requestOptions.credentialScheme.vcType!!) == true
            SD_JWT -> it.sdJwtVcType == requestOptions.credentialScheme.sdJwtType!!
            ISO_MDOC -> it.docType == requestOptions.credentialScheme.isoDocType!!
        }
    }?.scope

    @Suppress("DEPRECATION")
    @Deprecated("Removed in OID4VCI draft 15, use createCredentialRequest with token response")
    sealed class CredentialRequestInput {
        /**
         * @param id from the token response, see [TokenResponseParameters.authorizationDetails]
         * and [OpenIdcredentialConfigurationId]
         */
        @Deprecated("Removed in OID4VCI draft 15, use createCredentialRequest with token response")
        data class CredentialIdentifier(val id: String) : CredentialRequestInput()

        @Deprecated("Removed in OID4VCI draft 15, use createCredentialRequest with token response")
        data class RequestOptions(val requestOptions: WalletService.RequestOptions) : CredentialRequestInput()

        @Deprecated("Removed in OID4VCI draft 15, use createCredentialRequest with token response")
        data class Format(
            val supportedCredentialFormat: SupportedCredentialFormat,
            @Deprecated("Removed in OID4VCI draft 15")
            val requestedAttributes: Set<String>? = null,
        ) : CredentialRequestInput()
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     *
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * see [TokenResponseParameters.toHttpHeaderValue].
     *
     * Be sure to include a DPoP header if [TokenResponseParameters.tokenType] is `DPoP`,
     * see [buildDPoPHeader].
     *
     * See [OAuth2Client.createTokenRequestParameters].
     *
     * Sample ktor code:
     * ```
     * val tokenResponse = ...
     * val credentialRequest = client.createCredentialRequest(
     *     tokenResponse = tokenResponse,
     *     credentialIssuer = issuerMetadata.credentialIssuer
     * ).getOrThrow()
     *
     * val credentialResponse = httpClient.post(issuerMetadata.credentialEndpointUrl) {
     *     setBody(credentialRequest)
     *     headers {
     *         append(HttpHeaders.Authorization, tokenResponse.toHttpHeaderValue())
     *     }
     * }
     * ```
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialFormat which credential to request (needed to build the correct proof)
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     */
    suspend fun createCredentialRequest(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<CredentialRequestParameters>> = catching {
        val requests = (tokenResponse.authorizationDetails?.toCredentialRequest()
            ?: tokenResponse.scope?.toCredentialRequest(metadata)).let {
            if (it.isNullOrEmpty())
                previouslyRequestedScope?.toCredentialRequest(metadata)
            else it
        }
        if (requests == null || requests.isEmpty()) {
            throw IllegalArgumentException("Can't parse tokenResponse: $tokenResponse")
        }
        requests.map {
            @Suppress("DEPRECATION")
            it.copy(
                proof = createCredentialRequestProof(
                    metadata = metadata,
                    credentialFormat = credentialFormat,
                    clientNonce = clientNonce ?: tokenResponse.clientNonce,
                    clock = clock
                ),
                credentialResponseEncryption = metadata.credentialResponseEncryption()
            )
        }.also {
            Napier.i("createCredentialRequest returns $it")
        }
    }

    private fun Set<AuthorizationDetails>.toCredentialRequest(): List<CredentialRequestParameters> =
        filterIsInstance<OpenIdAuthorizationDetails>().flatMap {
            require(it.credentialIdentifiers != null) { "credential_identifiers are null" }
            it.credentialIdentifiers!!.map {
                CredentialRequestParameters(credentialIdentifier = it)
            }
        }

    private fun String.toCredentialRequest(metadata: IssuerMetadata): Set<CredentialRequestParameters> =
        trim().split(" ").mapNotNull { scope ->
            metadata.supportedCredentialConfigurations
                ?.entries?.firstOrNull { it.value.scope == scope }
                ?.let {
                    @Suppress("DEPRECATION")
                    CredentialRequestParameters(
                        credentialConfigurationId = it.key,
                        format = it.value.format,
                        sdJwtVcType = it.value.sdJwtVcType,
                        docType = it.value.docType,
                        credentialDefinition = it.value.credentialDefinition
                    )
                }
                ?: null.also { Napier.w("createCredentialRequest unknown scope $scope") }
        }.toSet()

    private fun IssuerMetadata.credentialResponseEncryption(): CredentialResponseEncryption? =
        if (requestEncryption && decryptionKeyMaterial != null && jweDecryptionService != null && credentialResponseEncryption != null) {
            CredentialResponseEncryption(
                jsonWebKey = decryptionKeyMaterial.jsonWebKey,
                jweAlgorithm = jwsService.encryptionAlgorithm,
                jweEncryptionString = jwsService.encryptionEncoding.text
            )
        } else null

    @Suppress("DEPRECATION")
    @Deprecated("Removed in OID4VCI draft 15", ReplaceWith("createCredentialRequest(tokenResponse, credentialIssuer)"))
    suspend fun createCredentialRequest(
        input: CredentialRequestInput,
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock = Clock.System,
    ): KmmResult<CredentialRequestParameters> = catching {
        when (input) {
            is CredentialRequestInput.CredentialIdentifier ->
                CredentialRequestParameters(credentialIdentifier = input.id)

            is CredentialRequestInput.Format ->
                input.supportedCredentialFormat.toCredentialRequestParameters()

            is CredentialRequestInput.RequestOptions -> with(input.requestOptions) {
                credentialScheme.toCredentialRequestParameters(representation)
            }
        }.copy(
            proof = createCredentialRequestProofJwt(clientNonce, credentialIssuer, clock)
        ).also { Napier.i("createCredentialRequest returns $it") }
    }

    internal suspend fun createCredentialRequestProof(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String?,
        clock: Clock = Clock.System,
    ): CredentialRequestProof =
        credentialFormat.supportedProofTypes?.get(ProofType.JWT.stringRepresentation)?.let {
            createCredentialRequestProofJwt(clientNonce, metadata.credentialIssuer, clock, it.keyAttestationRequired())
        } ?: credentialFormat.supportedProofTypes?.get(ProofType.ATTESTATION.stringRepresentation)?.let {
            createCredentialRequestProofAttestation(clientNonce, it.supportedSigningAlgorithms)
        } ?: createCredentialRequestProofJwt(clientNonce, metadata.credentialIssuer, clock)

    private fun CredentialRequestProofSupported.keyAttestationRequired(): Boolean =
        keyAttestationRequired != null

    internal suspend fun createCredentialRequestProofAttestation(
        clientNonce: String?,
        supportedSigningAlgorithms: Collection<String>,
    ): CredentialRequestProof = CredentialRequestProof(
        proofType = ProofType.ATTESTATION,
        attestation = this.loadKeyAttestation?.invoke(KeyAttestationInput(clientNonce, supportedSigningAlgorithms))
            ?.getOrThrow()?.serialize()
            ?: throw IllegalArgumentException("Key attestation required, none provided")
    )

    internal suspend fun createCredentialRequestProofJwt(
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock = Clock.System,
        addKeyAttestation: Boolean = false,
    ): CredentialRequestProof = CredentialRequestProof(
        proofType = ProofType.JWT,
        jwt = buildJwtProof(addKeyAttestation, clientNonce, credentialIssuer, clock)
    )

    private suspend fun buildJwtProof(
        addKeyAttestation: Boolean,
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock,
    ): String = jwsService.createSignedJwsAddingParams(
        header = JwsHeader(
            algorithm = cryptoService.keyMaterial.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
            type = OpenIdConstants.PROOF_JWT_TYPE,
            keyAttestation = if (addKeyAttestation)
                this.loadKeyAttestation?.invoke(KeyAttestationInput(clientNonce, null))?.getOrThrow()?.serialize()
                    ?: throw IllegalArgumentException("Key attestation required, none provided")
            else null
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


    private fun ConstantIndex.CredentialScheme.toCredentialRequestParameters(
        representation: CredentialRepresentation,
    ) = CredentialRequestParameters(
        credentialConfigurationId = when {
            representation == PLAIN_JWT && supportsVcJwt -> toCredentialIdentifier(representation)
            representation == SD_JWT && supportsSdJwt -> toCredentialIdentifier(representation)
            representation == ISO_MDOC && supportsIso -> toCredentialIdentifier(representation)
            else -> throw IllegalArgumentException("format $representation not applicable to $this")
        }
    )

    private fun SupportedCredentialFormat.toCredentialRequestParameters() =
        CredentialRequestParameters(
            credentialConfigurationId = scope
        )
}
