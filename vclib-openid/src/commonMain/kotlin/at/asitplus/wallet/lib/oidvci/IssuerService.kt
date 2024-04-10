package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofTypes
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.coroutines.cancellation.CancellationException

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
     * Used as [IssuerMetadata.authorizationServer].
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
        this.vcType to SupportedCredentialFormat(
            format = CredentialFormatEnum.JWT_VC,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType),
                credentialSubject = this.claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = listOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        ),
        this.vcType to SupportedCredentialFormat(
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
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    fun authorize(params: AuthenticationRequestParameters): String? {
        val builder = URLBuilder(params.redirectUrl ?: return null)
        builder.parameters.append(OpenIdConstants.GRANT_TYPE_CODE, codeService.provideCode())
        return builder.buildString()
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     */
    @Throws(OAuth2Exception::class)
    fun token(params: TokenRequestParameters): TokenResponseParameters {
        if (!codeService.verifyCode(params.code))
            throw OAuth2Exception(Errors.INVALID_CODE)
        return TokenResponseParameters(
            accessToken = tokenService.provideToken(),
            tokenType = TOKEN_TYPE_BEARER,
            expires = 3600,
            clientNonce = clientNonceService.provideNonce()
        )
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
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun credential(
        authorizationHeader: String,
        params: CredentialRequestParameters
    ): CredentialResponseParameters {
        if (!tokenService.verifyToken(authorizationHeader.removePrefix(TOKEN_PREFIX_BEARER)))
            throw OAuth2Exception(Errors.INVALID_TOKEN)
        val proof = params.proof
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        if (proof.proofType != ProofTypes.JWT)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwsSigned = JwsSigned.parse(proof.proof)
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString()).getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwsSigned.header.type != ProofTypes.JWT_HEADER_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val subjectPublicKey = jwsSigned.header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)

        val issuedCredentialResult = issuer.issueCredential(
            subjectPublicKey = subjectPublicKey,
            attributeTypes = params.types.toList(),
            representation = params.format.toRepresentation(),
            claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }
        )
        if (issuedCredentialResult.successful.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        return issuedCredentialResult.successful.first().toCredentialResponseParameters()
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