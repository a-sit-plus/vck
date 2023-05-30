package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofTypes
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import io.ktor.http.URLBuilder
import kotlin.coroutines.cancellation.CancellationException

/**
 * Server implementation to issue credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class IssuerService(
    private val issuer: Issuer,
    private val credentialSchemes: Collection<ConstantIndex.CredentialScheme>,
    private val codeService: CodeService = DefaultCodeService(),
    private val tokenService: TokenService = DefaultTokenService(),
    private val clientNonceService: NonceService = DefaultNonceService(),
    private val authorizationServer: String? = null,
    private val publicContext: String = "https://wallet.a-sit.at/",
    private val authorizationEndpointPath: String = "/authorize",
    private val tokenEndpointPath: String = "/token",
    private val credentialEndpointPath: String = "/credential",
) {

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     */
    val metadata: IssuerMetadata by lazy {
        val credentialFormats = credentialSchemes.map {
            SupportedCredentialFormat(
                format = CredentialFormatEnum.JWT_VC,
                id = it.vcType,
                types = arrayOf(VERIFIABLE_CREDENTIAL, it.vcType),
                supportedBindingMethods = arrayOf("did:key", URN_TYPE_JWK_THUMBPRINT),
                supportedCryptographicSuites = arrayOf(JwsAlgorithm.ES256.text),
            )
        }
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServer = authorizationServer,
            authorizationEndpointUrl = "$publicContext$authorizationEndpointPath",
            tokenEndpointUrl = "$publicContext$tokenEndpointPath",
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            supportedCredentialFormat = credentialFormats.toTypedArray(),
            displayProperties = credentialSchemes
                .map { DisplayProperties(it.credentialDefinitionName, "en") }
                .toTypedArray()
        )
    }

    /**
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    fun authorize(params: AuthorizationRequestParameters): String {
        val builder = URLBuilder(params.redirectUrl)
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
        val jwsSigned = JwsSigned.parse(proof.jwt)
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString())
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwsSigned.header.type != ProofTypes.JWT_HEADER_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val subjectId = jwsSigned.header.publicKey?.identifier
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        val credential = issuer.issueCredentialWithTypes(subjectId, params.types.toList())
        if (credential.successful.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        return CredentialResponseParameters(
            format = CredentialFormatEnum.JWT_VC,
            credential = credential.successful.first().vcJws
        )
    }

}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}