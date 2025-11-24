package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Holder.StoreCredentialInput.Iso
import at.asitplus.wallet.lib.agent.Holder.StoreCredentialInput.SdJwt
import at.asitplus.wallet.lib.agent.Holder.StoreCredentialInput.Vc
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.CredentialIssuer.CredentialResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlin.time.Clock
import kotlinx.serialization.json.decodeFromJsonElement
import kotlin.collections.map

/**
 * Client service to retrieve credentials using OID4VCI
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class WalletService(
    /** Used as the issuer in credential proofs. Must match the `client_id` of the OAuth client. */
    val clientId: String = "https://wallet.a-sit.at/app",
    /** Used to prove possession of the key material for [CredentialRequestProofContainer], i.e., the holder key. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /** Load key attestation to create [CredentialRequestProofContainer], if required by the credential issuer. */
    private val loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsSigned<KeyAttestationJwt>>)? = null,
    /** Handles credential request encryption and credential response decryption. */
    private val encryptionService: WalletEncryptionService = WalletEncryptionService(),
) {

    data class KeyAttestationInput(val clientNonce: String?, val supportedAlgorithms: Collection<String>?)

    sealed interface CredentialRequest {
        /**
         * Send [request] as JSON-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/json` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JSON]).
         */
        data class Plain(val request: CredentialRequestParameters) : CredentialRequest

        /**
         * Send [request] as JWE-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/jwt` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JWT]).
         */
        data class Encrypted(val request: JweEncrypted) : CredentialRequest

        companion object {
            fun parse(input: String): KmmResult<CredentialRequest> = catching {
                if (input.count { it == '.' } == 4)
                    Encrypted(JweEncrypted.deserialize(input).getOrThrow())
                else
                    Plain(joseCompliantSerializer.decodeFromString<CredentialRequestParameters>(input))
            }
        }
    }

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
         * Opaque value which will be returned by the OpenId Provider
         */
        val state: String = uuid4().toString(),
    )

    /**
     * Pass in the URL provided by the Credential Issuer,
     * which may contain a direct [CredentialOffer] or a URI pointing to it.
     */
    suspend fun parseCredentialOffer(input: String): KmmResult<CredentialOffer> = catching {
        catching {
            input.extractParams().fetchCredentialOffer()
        }.getOrNull() ?: catchingUnwrapped {
            joseCompliantSerializer.decodeFromString<CredentialOffer>(input)
        }.getOrElse {
            throw InvalidRequest("could not parse credential offer", it)
        }
    }

    private fun String.extractParams(): CredentialOfferUrlParameters =
        Url(this).parameters.flattenEntries().toMap().decodeFromUrlQuery<CredentialOfferUrlParameters>()

    private suspend fun CredentialOfferUrlParameters.fetchCredentialOffer(

    ): CredentialOffer? = credentialOffer?.let { joseCompliantSerializer.decodeFromJsonElement<CredentialOffer>(it) }
        ?: credentialOfferUrl
            ?.let { remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(it)) }
            ?.let { parseCredentialOffer(it).getOrNull() }


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
     * Creates the credential request to be sent to the credential issuer.
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * see [TokenResponseParameters.toHttpHeaderValue].
     * Be sure to include a DPoP header if [TokenResponseParameters.tokenType] is `DPoP`,
     * see [BuildDPoPHeader].
     * For sample ktor code see `OpenId4VciClient` in `vck-openid-ktor`.
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialFormat which credential to request (needed to build the correct proof)
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     */
    suspend fun createCredential(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<CredentialRequest>> = catching {
        createCredentialRequestInternal(
            tokenResponse = tokenResponse,
            metadata = metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope,
            clock = clock
        ).getOrThrow().map {
            encryptionService.wrapCredentialRequest(it, metadata).getOrThrow()
        }
    }

    private suspend fun createCredentialRequestInternal(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<CredentialRequestParameters>> = catching {
        val requests = if (tokenResponse.authorizationDetails != null) {
            tokenResponse.authorizationDetails!!.toCredentialRequest()
        } else if (tokenResponse.scope != null) {
            tokenResponse.scope!!.toCredentialRequest(metadata)
        } else if (previouslyRequestedScope != null) {
            previouslyRequestedScope.toCredentialRequest(metadata)
        } else {
            throw InvalidToken("Can't parse token: $tokenResponse")
        }
        requests.map {
            createCredentialRequestProof(
                metadata = metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
                clock = clock
            ).let { proof ->
                it.copy(
                    proofs = proof,
                    credentialResponseEncryption = encryptionService.credentialResponseEncryption(metadata)
                )
            }
        }.also {
            Napier.i("createCredentialRequest returns $it")
        }
    }

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * decrypting the response if required.
     */
    public suspend fun parseCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        representation: CredentialRepresentation,
        scheme: ConstantIndex.CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        response.decryptIfNeeded(isEncrypted)
            .extractCredentials()
            .map { it.toStoreCredentialInput(representation, scheme) }
    }

    private suspend fun String.decryptIfNeeded(encrypted: Boolean) = if (encrypted)
        encryptionService.decryptToCredentialResponse(this).getOrThrow()
    else
        joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(this)

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * decrypting the response if required.
     */
    public suspend fun parseCredentialResponse(
        response: CredentialResponse,
        representation: CredentialRepresentation,
        scheme: ConstantIndex.CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        response.decryptIfNeeded()
            .extractCredentials()
            .map { it.toStoreCredentialInput(representation, scheme) }
    }

    private suspend fun CredentialResponse.decryptIfNeeded() = when (this) {
        is CredentialResponse.Plain -> response
        is CredentialResponse.Encrypted -> encryptionService.decryptToCredentialResponse(response).getOrThrow()
    }

    private fun Set<AuthorizationDetails>.toCredentialRequest(): List<CredentialRequestParameters> =
        filterIsInstance<OpenIdAuthorizationDetails>().flatMap {
            if (it.credentialIdentifiers != null && it.credentialIdentifiers?.isNotEmpty() == true) {
                it.credentialIdentifiers!!.map { CredentialRequestParameters(credentialIdentifier = it) }
            } else if (it.credentialConfigurationId != null && it.credentialConfigurationId?.isNotEmpty() == true) {
                listOf(CredentialRequestParameters(credentialConfigurationId = it.credentialConfigurationId!!))
            } else throw InvalidToken("Invalid authorization details: $it")
        }

    private fun String.toCredentialRequest(metadata: IssuerMetadata): Set<CredentialRequestParameters> =
        trim().split(" ").map { scope ->
            metadata.supportedCredentialConfigurations
                ?.entries?.firstOrNull { it.value.scope == scope }?.key
                ?.let { CredentialRequestParameters(credentialConfigurationId = it) }
                ?: throw OAuth2Exception.UnknownCredentialConfiguration(scope)
        }.toSet()

    internal suspend fun createCredentialRequestProof(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String?,
        clock: Clock = Clock.System,
    ): CredentialRequestProofContainer =
        credentialFormat.supportedProofTypes?.get(ProofTypes.JWT)?.let {
            createCredentialRequestProofJwt(clientNonce, metadata.credentialIssuer, clock, it.keyAttestationRequired())
        } ?: credentialFormat.supportedProofTypes?.get(ProofTypes.ATTESTATION)?.let {
            createCredentialRequestProofAttestation(clientNonce, it.supportedSigningAlgorithms)
        } ?: createCredentialRequestProofJwt(clientNonce, metadata.credentialIssuer, clock)

    private fun CredentialRequestProofSupported.keyAttestationRequired(): Boolean =
        keyAttestationRequired != null

    internal suspend fun createCredentialRequestProofAttestation(
        clientNonce: String?,
        supportedSigningAlgorithms: Collection<String>?,
    ) = CredentialRequestProofContainer(
        attestation = setOf(
            this.loadKeyAttestation?.invoke(KeyAttestationInput(clientNonce, supportedSigningAlgorithms))
                ?.getOrThrow()?.serialize()
                ?: throw IllegalArgumentException("Key attestation required, none provided")
        )
    )

    internal suspend fun createCredentialRequestProofJwt(
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock = Clock.System,
        addKeyAttestation: Boolean = false,
    ) = CredentialRequestProofContainer(
        jwt = setOf(
            SignJwt<JsonWebToken>(
                keyMaterial,
                // TODO To be refactored once signJwt is not passed in the constructor but to this function
                addKeyAttestationToJwsHeader(clientNonce, addKeyAttestation)
            ).invoke(
                OpenIdConstants.PROOF_JWT_TYPE,
                JsonWebToken(
                    issuer = clientId, // omit when token was pre-authn?
                    audience = credentialIssuer,
                    issuedAt = clock.now(),
                    nonce = clientNonce,
                ),
                JsonWebToken.serializer(),
            ).getOrThrow().serialize()
        )
    )

    private fun addKeyAttestationToJwsHeader(
        clientNonce: String?,
        addKeyAttestation: Boolean = false,
    ): suspend (JwsHeader, KeyMaterial) -> JwsHeader = { header: JwsHeader, key: KeyMaterial ->
        val keyAttestation = if (addKeyAttestation) {
            this.loadKeyAttestation?.invoke(KeyAttestationInput(clientNonce, null))?.getOrThrow()?.serialize()
                ?: throw IllegalArgumentException("Key attestation required, none provided")
        } else null
        header.copy(jsonWebKey = key.jsonWebKey, keyAttestation = keyAttestation)
    }

    @Throws(Exception::class)
    private fun String.toStoreCredentialInput(
        credentialRepresentation: CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme,
    ): Holder.StoreCredentialInput = when (credentialRepresentation) {
        PLAIN_JWT -> Vc(
            signedVcJws = JwsSigned.deserialize(VerifiableCredentialJws.serializer(), this, vckJsonSerializer)
                .getOrThrow(),
            vcJws = this,
            scheme = credentialScheme
        )

        SD_JWT -> SdJwt(
            signedSdJwtVc = SdJwtSigned.parseCatching(this).getOrThrow(),
            vcSdJwt = this,
            scheme = credentialScheme
        )

        ISO_MDOC -> catchingUnwrapped {
            Iso(
                issuerSigned = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(decodeToByteArray(Base64())),
                scheme = credentialScheme
            )
        }.getOrElse { throw Exception("Invalid credential format: $this", it) }
    }

}
