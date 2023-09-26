package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.cbor.CoseEllipticCurve
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.CoseKeyType
import at.asitplus.wallet.lib.data.Base64UrlStrict
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DOC_TYPE_MDL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsSigned
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
import io.ktor.http.URLBuilder
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
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
            when (it.credentialFormat) {
                ConstantIndex.CredentialFormat.ISO_18013 -> SupportedCredentialFormat(
                    format = CredentialFormatEnum.MSO_MDOC,
                    id = it.vcType,
                    types = arrayOf(it.vcType),
                    docType = DOC_TYPE_MDL,
                    claims = mapOf(
                        NAMESPACE_MDL to mapOf(
                            DataElements.GIVEN_NAME to RequestedCredentialClaimSpecification(),
                            DataElements.FAMILY_NAME to RequestedCredentialClaimSpecification(),
                            DataElements.DOCUMENT_NUMBER to RequestedCredentialClaimSpecification(),
                            DataElements.ISSUE_DATE to RequestedCredentialClaimSpecification(),
                            DataElements.EXPIRY_DATE to RequestedCredentialClaimSpecification(),
                            DataElements.DRIVING_PRIVILEGES to RequestedCredentialClaimSpecification(),
                        )
                    ),
                    supportedBindingMethods = arrayOf(BINDING_METHOD_COSE_KEY),
                    supportedCryptographicSuites = arrayOf(JwsAlgorithm.ES256.text),
                )

                ConstantIndex.CredentialFormat.W3C_VC -> SupportedCredentialFormat(
                    format = CredentialFormatEnum.JWT_VC,
                    id = it.vcType,
                    types = arrayOf(VERIFIABLE_CREDENTIAL, it.vcType),
                    supportedBindingMethods = arrayOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
                    supportedCryptographicSuites = arrayOf(JwsAlgorithm.ES256.text),
                )
            }
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
        val jwsSigned = JwsSigned.parse(proof.jwt)
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString())
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwsSigned.header.type != ProofTypes.JWT_HEADER_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val subjectPublicKey = jwsSigned.header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)

        val issuedCredentialResult = issuer.issueCredentialWithTypes(
            subjectId = subjectPublicKey.identifier,
            subjectPublicKey = subjectPublicKey.toCryptoPublicKey(),
            attributeTypes = params.types.toList()
        )
        if (issuedCredentialResult.successful.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }

        return when (val issuedCredential = issuedCredentialResult.successful.first()) {
            is Issuer.IssuedCredential.Iso -> CredentialResponseParameters(
                format = CredentialFormatEnum.MSO_MDOC,
                credential = issuedCredential.issuerSigned.serialize().encodeToString(Base64UrlStrict),
            )

            is Issuer.IssuedCredential.VcJwt -> CredentialResponseParameters(
                format = CredentialFormatEnum.JWT_VC,
                credential = issuedCredential.vcJws,
            )

            is Issuer.IssuedCredential.VcSdJwt -> CredentialResponseParameters(
                format = CredentialFormatEnum.JWT_VC, // TODO correct type
                credential = issuedCredential.vcSdJwt,
            )
        }
    }

}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}