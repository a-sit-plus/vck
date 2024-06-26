package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.crypto.datatypes.cose.CborWebToken
import at.asitplus.crypto.datatypes.cose.CoseHeader
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.ConstantIndex.supportsIso
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OidcSiopVerifier.AuthnResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.wallet.lib.oidc.OpenIdConstants.CREDENTIAL_TYPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlin.random.Random

/**
 * Client service to retrieve credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
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
    private val cryptoService: CryptoService = DefaultCryptoService(RandomKeyPairAdapter()),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val coseService: CoseService = DefaultCoseService(cryptoService),
) {

    constructor(
        /**
         * Used to create [AuthenticationRequestParameters], [TokenRequestParameters] and [CredentialRequestProof],
         * typically a URI.
         */
        clientId: String = "https://wallet.a-sit.at/app",
        /**
         * Used to create [AuthenticationRequestParameters] and [TokenRequestParameters].
         */
        redirectUrl: String = "$clientId/callback",
        keyPairAdapter: KeyPairAdapter,
    ) : this(
        clientId = clientId,
        redirectUrl = redirectUrl,
        cryptoService = DefaultCryptoService(keyPairAdapter),
    )

    private val stateToCodeChallengeMap = mutableMapOf<String, String>()
    private val codeChallengeMutex = Mutex()

    companion object {
        fun newDefaultInstance(
            clientId: String,
            redirectUrl: String,
            cryptoService: CryptoService
        ): WalletService = WalletService(
            clientId = clientId,
            redirectUrl = redirectUrl,
            cryptoService = cryptoService,
            jwsService = DefaultJwsService(cryptoService),
            coseService = DefaultCoseService(cryptoService),
        )
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
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl]).
     *
     * Sample ktor code:
     * ```
     * val credentialConfig = issuerMetadata.supportedCredentialConfigurations!!
     *     .entries.first { it.key == credentialOffer.configurationIds.first() }.toPair()
     * val authnRequest = client.createAuthRequest(
     *     state = state,
     *     credential = credentialConfig,
     *     credentialIssuer = issuerMetadata.credentialIssuer,
     *     authorizationServers = issuerMetadata.authorizationServers
     * )
     * val authnResponse = httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * val authn = AuthenticationResponseParameters.deserialize(authnResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param credential which credential from [IssuerMetadata.supportedCredentialConfigurations] to request
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    suspend fun createAuthRequest(
        state: String,
        credential: Pair<String, SupportedCredentialFormat>,
        credentialIssuer: String? = null,
        authorizationServers: Set<String>? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        authorizationDetails = setOf(credential.toAuthnDetails(authorizationServers)),
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl]).
     *
     * Sample ktor code:
     * ```
     * val authnRequest = client.createAuthRequest(
     *     requestOptions = requestOptions,
     *     credentialIssuer = issuerMetadata.credentialIssuer,
     * )
     * val authnResponse = httpClient.get(issuerMetadata.authorizationEndpointUrl!!) {
     *     url {
     *         authnRequest.encodeToParameters().forEach { parameters.append(it.key, it.value) }
     *     }
     * }
     * val authn = AuthenticationResponseParameters.deserialize(authnResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param requestOptions which credential in which representation to request
     * @param credentialIssuer from [IssuerMetadata.credentialIssuer]
     */
    suspend fun createAuthRequest(
        requestOptions: RequestOptions,
        credentialIssuer: String? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = requestOptions.state,
        clientId = clientId,
        authorizationDetails = requestOptions.toAuthnDetails()?.let { setOf(it) },
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(requestOptions.state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun generateCodeVerifier(state: String): String {
        val codeVerifier = Random.nextBytes(32).toHexString(HexFormat.Default)
        codeChallengeMutex.withLock { stateToCodeChallengeMap.put(state, codeVerifier) }
        return codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
    }

    /**
     * Request token with an authorization code, e.g. from [createAuthRequest].
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl]).
     *
     * Sample ktor code:
     * ```
     * val authnRequest = client.createAuthRequest(requestOptions)
     * val authnResponse = authorizationService.authorize(authnRequest).getOrThrow()
     * val code = authnResponse.params.code
     * val tokenRequest = client.createTokenRequestParameters(requestOptions, code = code)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createTokenRequestParameters(
        requestOptions: RequestOptions,
        code: String,
    ) = TokenRequestParameters(
        grantType = GRANT_TYPE_CODE,
        code = code,
        redirectUrl = redirectUrl,
        clientId = clientId,
        authorizationDetails = requestOptions.toAuthnDetails()?.let { setOf(it) },
        codeVerifier = codeChallengeMutex.withLock { stateToCodeChallengeMap.remove(requestOptions.state) }
    )

    /**
     * Request token with pre-auth-code, e.g. from [CredentialOffer].
     *
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl]).
     *
     * Sample ktor code:
     * ```
     * val tokenRequest =
     *     client.createTokenRequestParameters(requestOptions, credentialOffer.grants!!.preAuthorizedCode)
     * val tokenResponse = httpClient.submitForm(
     *     url = issuerMetadata.tokenEndpointUrl!!,
     *     formParameters = parameters {
     *         tokenRequest.encodeToParameters().forEach { append(it.key, it.value) }
     *     }
     * )
     * val token = TokenResponseParameters.deserialize(tokenResponse.bodyAsText()).getOrThrow()
     * ```
     *
     * @param requestOptions which credential in which representation to request
     * @param preAuthCode from [CredentialOfferGrants.preAuthorizedCode] in [CredentialOffer.grants]
     */
    suspend fun createTokenRequestParameters(
        requestOptions: RequestOptions,
        preAuthCode: CredentialOfferGrantsPreAuthCode?,
    ) = TokenRequestParameters(
        grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
        redirectUrl = redirectUrl,
        clientId = clientId,
        authorizationDetails = requestOptions.toAuthnDetails()?.let { setOf(it) },
        transactionCode = preAuthCode?.transactionCode,
        preAuthorizedCode = preAuthCode?.preAuthorizedCode,
        codeVerifier = codeChallengeMutex.withLock { stateToCodeChallengeMap.remove(requestOptions.state) }
    )

    private fun RequestOptions.toAuthnDetails() =
        representation.toAuthorizationDetails(credentialScheme, requestedAttributes)

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     *
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     * See [createTokenRequestParameters].
     *
     * Sample ktor code:
     * ```
     * val credentialRequest = client.createCredentialRequestJwt(
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
     * @param requestOptions which credential in which representation to request
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequestJwt(
        requestOptions: RequestOptions,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        val proofPayload = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = cryptoService.keyPairAdapter.signingAlgorithm.toJwsAlgorithm(),
                type = OpenIdConstants.ProofType.JWT_HEADER_TYPE.stringRepresentation,
            ),
            payload = JsonWebToken(
                issuer = clientId, // TODO omit if token was pre-authn
                audience = credentialIssuer,
                issuedAt = requestOptions.clock.now(),
                nonce = clientNonce,
            ).serialize().encodeToByteArray(),
            addKeyId = false,
            addJsonWebKey = true,
            addX5c = true,
        ).getOrThrow()
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofType.JWT,
            jwt = proofPayload.serialize()
        )
        requestOptions.toCredentialRequestJwt(proof)
            .also { Napier.i("createCredentialRequestJwt returns $it") }
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * as value `Bearer <accessTokenValue>` (depending on the [TokenResponseParameters.tokenType]).
     *
     * Sample ktor code:
     * ```
     * val credentialRequest = client.createCredentialRequestCwt(
     *     requestOptions = WalletService.RequestOptions(
     *         credentialScheme = MobileDrivingLicenceScheme,
     *         representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
     *         state = state
     *     ),
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
     * @param requestOptions which credential in which representation to request
     * @param clientNonce `c_nonce` from the token response, optional string, see [TokenResponseParameters.clientNonce]
     * @param credentialIssuer `credential_issuer` from the metadata, see [IssuerMetadata.credentialIssuer]
     */
    suspend fun createCredentialRequestCwt(
        requestOptions: RequestOptions,
        clientNonce: String?,
        credentialIssuer: String?,
    ): KmmResult<CredentialRequestParameters> = catching {
        val proofPayload = coseService.createSignedCose(
            protectedHeader = CoseHeader(
                algorithm = cryptoService.keyPairAdapter.signingAlgorithm.toCoseAlgorithm(),
                contentType = OpenIdConstants.ProofType.CWT_HEADER_TYPE.stringRepresentation,
                certificateChain = cryptoService.keyPairAdapter.certificate?.encodeToDerOrNull()
            ),
            payload = CborWebToken(
                issuer = clientId, // TODO omit when pre-authn
                audience = credentialIssuer,
                issuedAt = requestOptions.clock.now(),
                nonce = clientNonce?.encodeToByteArray(),
            ).serialize(),
            addKeyId = false,
        ).getOrThrow()
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofType.CWT,
            cwt = proofPayload.serialize().encodeToString(Base64UrlStrict),
        )
        requestOptions.toCredentialRequestJwt(proof)
            .also { Napier.i("createCredentialRequestCwt returns $it") }
    }

    private fun RequestOptions.toCredentialRequestJwt(proof: CredentialRequestProof) =
        representation.toCredentialRequestParameters(
            credentialScheme,
            requestedAttributes,
            proof
        )

    private fun CredentialRepresentation.toAuthorizationDetails(
        scheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?
    ): AuthorizationDetails? = when (this) {
        PLAIN_JWT -> scheme.toJwtAuthn(toFormat())
        SD_JWT -> scheme.toSdJwtAuthn(toFormat(), requestedAttributes)
        ISO_MDOC -> scheme.toIsoAuthn(toFormat(), requestedAttributes)
    }

    private fun ConstantIndex.CredentialScheme.toJwtAuthn(
        format: CredentialFormatEnum
    ) = if (supportsVcJwt)
        AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType!!),
            ),
        )
    else null

    private fun ConstantIndex.CredentialScheme.toSdJwtAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?
    ) = if (supportsSdJwt)
        AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = format,
            sdJwtVcType = sdJwtType!!,
            claims = requestedAttributes?.toRequestedClaimsSdJwt(this),
        ) else null

    private fun ConstantIndex.CredentialScheme.toIsoAuthn(
        format: CredentialFormatEnum,
        requestedAttributes: Set<String>?
    ) = if (supportsIso) AuthorizationDetails(
        type = CREDENTIAL_TYPE_OPENID,
        format = format,
        docType = isoDocType,
        claims = requestedAttributes?.toRequestedClaimsIso(this)
    ) else null

    private fun CredentialRepresentation.toCredentialRequestParameters(
        credentialScheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Set<String>?,
        proof: CredentialRequestProof
    ) = when {
        this == PLAIN_JWT && credentialScheme.supportsVcJwt -> CredentialRequestParameters(
            format = toFormat(),
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType!!,
            ),
            proof = proof
        )

        this == SD_JWT && credentialScheme.supportsSdJwt -> CredentialRequestParameters(
            format = toFormat(),
            claims = requestedAttributes?.toRequestedClaimsSdJwt(credentialScheme),
            sdJwtVcType = credentialScheme.sdJwtType!!,
            proof = proof
        )

        this == ISO_MDOC && credentialScheme.supportsIso -> CredentialRequestParameters(
            format = toFormat(),
            docType = credentialScheme.isoDocType,
            claims = requestedAttributes?.toRequestedClaimsIso(credentialScheme),
            proof = proof
        )

        else -> throw IllegalArgumentException("format $this not applicable to $credentialScheme")
    }
}

private fun Pair<String, SupportedCredentialFormat>.toAuthnDetails(authorizationServers: Set<String>?)
        : AuthorizationDetails = AuthorizationDetails(
    type = "openid_credential",
    credentialConfigurationId = first,
    format = second.format,
    docType = second.docType,
    sdJwtVcType = second.sdJwtVcType,
    credentialDefinition = second.credentialDefinition,
    locations = authorizationServers
)

private fun Collection<String>.toRequestedClaimsSdJwt(credentialScheme: ConstantIndex.CredentialScheme) =
    mapOf(credentialScheme.sdJwtType!! to this.associateWith { RequestedCredentialClaimSpecification() })

private fun Collection<String>.toRequestedClaimsIso(credentialScheme: ConstantIndex.CredentialScheme) =
    mapOf(credentialScheme.isoNamespace!! to this.associateWith { RequestedCredentialClaimSpecification() })


private fun CredentialRepresentation.toFormat() = when (this) {
    PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    SD_JWT -> CredentialFormatEnum.VC_SD_JWT
    ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}
