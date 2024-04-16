package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofTypes
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Server implementation to issue credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class IssuerService(
    /**
     * Used to actually issue the credential.
     */
    private val issuer: Issuer,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Collection<ConstantIndex.CredentialScheme>,
    /**
     * Used to create and verify authorization codes during issuing.
     */
    private val codeService: CodeService = DefaultCodeService(),
    /**
     * Used to create and verify bearer tokens during issuing.
     */
    private val tokenService: TokenService = DefaultTokenService(),
    /**
     * Used to provide challenge to clients to include in proof of posession of key material.
     */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /**
     * Used as [IssuerMetadata.authorizationServers].
     */
    private val authorizationServer: String? = null,
    /**
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    private val publicContext: String = "https://wallet.a-sit.at/",
    /**
     * Used to build [IssuerMetadata.authorizationEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [authorize].
     */
    private val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [IssuerMetadata.tokenEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    private val tokenEndpointPath: String = "/token",
    /**
     * Used to build [IssuerMetadata.credentialEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [credential].
     */
    private val credentialEndpointPath: String = "/credential",
) {

    private val codeToCodeChallengeMap = mutableMapOf<String, String>()
    private val codeChallengeMutex = Mutex()

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     */
    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServers = authorizationServer?.let { listOf(it) },
            authorizationEndpointUrl = "$publicContext$authorizationEndpointPath",
            tokenEndpointUrl = "$publicContext$tokenEndpointPath",
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            supportedCredentialConfigurations = mutableMapOf<String, SupportedCredentialFormat>().apply {
                credentialSchemes.forEach { putAll(it.toSupportedCredentialFormat()) }
            },
            supportsCredentialIdentifiers = true,
            displayProperties = credentialSchemes.map { DisplayProperties(it.vcType, "en") }
        )
    }

    private fun ConstantIndex.CredentialScheme.toSupportedCredentialFormat() = mapOf(
        this.isoNamespace to SupportedCredentialFormat(
            format = CredentialFormatEnum.MSO_MDOC,
            docType = isoDocType,
            claims = mapOf(
                isoNamespace to claimNames
                    .associateWith { RequestedCredentialClaimSpecification() }
            ),
            supportedBindingMethods = listOf(BINDING_METHOD_COSE_KEY),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        ),
        "$vcType-${CredentialFormatEnum.JWT_VC.text}" to SupportedCredentialFormat(
            format = CredentialFormatEnum.JWT_VC,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType),
                credentialSubject = this.claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = listOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        ),
        "$vcType-${CredentialFormatEnum.VC_SD_JWT.text}" to SupportedCredentialFormat(
            format = CredentialFormatEnum.VC_SD_JWT,
            sdJwtVcType = vcType,
            claims = mapOf(
                isoNamespace to claimNames
                    .associateWith { RequestedCredentialClaimSpecification() }
            ),
            supportedBindingMethods = listOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        )
    )

    /**
     * Offer all [credentialSchemes] to clients.
     * Callers may need to transport this in [CredentialOfferUrlParameters] to (HTTPS) clients.
     */
    fun credentialOffer(): CredentialOffer = CredentialOffer(
        credentialIssuer = publicContext,
        configurationIds = credentialSchemes.map { it.vcType },
        grants = CredentialOfferGrants(
            authorizationCode = CredentialOfferGrantsAuthCode(
                issuerState = uuid4().toString(), // TODO remember this state, for subsequent requests from the Wallet
                authorizationServer = publicContext // may need to support external AS?
            ),
            preAuthorizedCode = CredentialOfferGrantsPreAuthCode(
                preAuthorizedCode = codeService.provideCode(),
                transactionCode = CredentialOfferGrantsPreAuthCodeTransactionCode(
                    inputMode = "numeric",
                    length = 16,
                ),
                authorizationServer = publicContext // may need to support external AS?,
            )
        )
    )

    /**
     * Builds the authentication response.
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    suspend fun authorize(request: AuthenticationRequestParameters): KmmResult<AuthenticationResponseResult> {
        // TODO Need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        if (request.redirectUrl == null)
            return KmmResult.failure<AuthenticationResponseResult>(
                OAuth2Exception(Errors.INVALID_REQUEST, "redirect_uri not set")
            ).also { Napier.w("authorize: client did not set redirect_uri in $request") }
        val code = codeService.provideCode()
        val responseParams = AuthenticationResponseParameters(
            code = code,
            state = request.state,
        )
        if (request.codeChallenge != null) {
            codeChallengeMutex.withLock {
                codeToCodeChallengeMap[code] = request.codeChallenge
            }
        }
        // TODO Also implement POST?
        val url = URLBuilder(request.redirectUrl)
            .apply { responseParams.encodeToParameters().forEach { this.parameters.append(it.key, it.value) } }
            .buildString()
        val result = AuthenticationResponseResult.Redirect(url, responseParams)
        Napier.i("authorize returns $result")
        return KmmResult.success(result)
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     *
     * @return [KmmResult] may contain a [OAuth2Exception]
     */
    suspend fun token(params: TokenRequestParameters): KmmResult<TokenResponseParameters> {
        // TODO This is part of the Authorization Server
        when (params.grantType) {
            GRANT_TYPE_CODE -> if (params.code == null || !codeService.verifyCode(params.code))
                return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_CODE))
                    .also { Napier.w("token: client did not provide correct code") }

            GRANT_TYPE_PRE_AUTHORIZED_CODE -> if (params.preAuthorizedCode == null || !codeService.verifyCode(params.preAuthorizedCode))
                return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                    .also { Napier.w("token: client did not provide pre authorized code") }

            else ->
                return KmmResult.failure<TokenResponseParameters>(
                    OAuth2Exception(Errors.INVALID_REQUEST, "No valid grant_type")
                ).also { Napier.w("token: client did not provide valid grant_type: ${params.grantType}") }
        }
        if (params.authorizationDetails != null) {
            // TODO verify params.authorizationDetails.claims and so on
            params.authorizationDetails.credentialIdentifiers?.forEach { credentialIdentifier ->
                if (!credentialSchemes.map { it.vcType }.contains(credentialIdentifier)) {
                    return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                        .also { Napier.w("token: client requested invalid credential identifier: $credentialIdentifier") }
                }
            }
        }
        params.codeVerifier?.let { codeVerifier ->
            val codeChallenge = codeChallengeMutex.withLock { codeToCodeChallengeMap.remove(params.code) }
            val codeChallengeCalculated = codeVerifier.encodeToByteArray().sha256()
                .encodeToString(Base64UrlStrict)
            if (codeChallenge != codeChallengeCalculated) {
                return KmmResult.failure<TokenResponseParameters>(OAuth2Exception(Errors.INVALID_GRANT))
                    .also { Napier.w("token: client did not provide correct code verifier: $codeVerifier") }
            }
        }
        val result = TokenResponseParameters(
            accessToken = tokenService.provideToken(),
            tokenType = TOKEN_TYPE_BEARER,
            expires = 3600,
            clientNonce = clientNonceService.provideNonce(),
            authorizationDetails = params.authorizationDetails?.let {
                // TODO supported credential identifiers!
                listOf(it)
            }
        )
        Napier.i("token returns $result")
        return KmmResult.success(result)
    }

    /**
     * Verifies the [authorizationHeader] to contain a token from [tokenService],
     * verifies the proof sent by the client (must contain a nonce from [clientNonceService]),
     * and issues credentials to the client.
     * Send the result JSON-serialized back to the client.
     *
     * @param authorizationHeader The value of HTTP header `Authorization` sent by the client
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     */
    suspend fun credential(
        authorizationHeader: String, // TODO Change interface to only contain access token, nothing else
        params: CredentialRequestParameters
    ): KmmResult<CredentialResponseParameters> {
        if (!tokenService.verifyToken(authorizationHeader.removePrefix(TOKEN_PREFIX_BEARER)))
            return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_TOKEN))
                .also { Napier.w("credential: client did not provide correct token: $authorizationHeader") }
        val proof = params.proof
            ?: return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("credential: client did not provide proof of possession") }
        // TODO also support `cwt` as proof
        if (proof.proofType != ProofTypes.JWT || proof.jwt == null)
            return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide invalid proof: $proof") }
        val jwsSigned = JwsSigned.parse(proof.jwt)
            ?: return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide invalid proof: $proof") }
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString()).getOrNull()
            ?: return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide invalid JWT in proof: $proof") }
        // TODO verify required claims in OID4VCI 7.2.1.1
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide invalid nonce in JWT in proof: ${jwt.nonce}") }
        if (jwsSigned.header.type != ProofTypes.JWT_HEADER_TYPE)
            return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide invalid header type in JWT in proof: ${jwsSigned.header}") }
        val subjectPublicKey = jwsSigned.header.publicKey
            ?: return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_PROOF))
                .also { Napier.w("credential: client did provide no valid key in header in JWT in proof: ${jwsSigned.header}") }

        val issuedCredentialResult = when {
            params.format != null -> {
                issuer.issueCredential(
                    subjectPublicKey = subjectPublicKey,
                    attributeTypes = listOfNotNull(params.sdJwtVcType, params.docType)
                            + (params.credentialDefinition?.types?.toList() ?: listOf()),
                    representation = params.format.toRepresentation(),
                    claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }
                )
            }

            params.credentialIdentifier != null -> {
                // TODO this delimiter is probably not safe
                val representation = CredentialFormatEnum.parse(params.credentialIdentifier.substringAfterLast("-"))
                    ?: return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                        .also { Napier.w("credential: client did not provide correct credential identifier: ${params.credentialIdentifier}") }
                // TODO what to do in case of ISO, look at string constants from EUDIW
                val vcType = params.credentialIdentifier.substringBeforeLast("-")
                issuer.issueCredential(
                    subjectPublicKey = subjectPublicKey,
                    attributeTypes = listOf(vcType),
                    representation = representation.toRepresentation(),
                    claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }
                )
            }

            else -> {
                return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                    .also { Napier.w("credential: client did not provide format or credential identifier in params: $params") }
            }
        }
        if (issuedCredentialResult.successful.isEmpty()) {
            return KmmResult.failure<CredentialResponseParameters>(OAuth2Exception(Errors.INVALID_REQUEST))
                .also { Napier.w("credential: issuer did not issue credential: $issuedCredentialResult") }
        }
        // TODO Implement Batch Credential Endpoint for more than one credential response
        val result = issuedCredentialResult.successful.first().toCredentialResponseParameters()
        Napier.i("credential returns $result")
        return KmmResult.success(result)
    }

    private fun Issuer.IssuedCredential.toCredentialResponseParameters() = when (this) {
        is Issuer.IssuedCredential.Iso -> CredentialResponseParameters(
            format = CredentialFormatEnum.MSO_MDOC,
            credential = issuerSigned.serialize().encodeToString(Base64UrlStrict),
        )

        is Issuer.IssuedCredential.VcJwt -> CredentialResponseParameters(
            format = CredentialFormatEnum.JWT_VC,
            credential = vcJws,
        )

        is Issuer.IssuedCredential.VcSdJwt -> CredentialResponseParameters(
            format = CredentialFormatEnum.VC_SD_JWT,
            credential = vcSdJwt,
        )
    }

}

private fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.JWT_VC_SD_UNOFFICIAL -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.VC_SD_JWT -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> ConstantIndex.CredentialRepresentation.ISO_MDOC
    else -> ConstantIndex.CredentialRepresentation.PLAIN_JWT
}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}