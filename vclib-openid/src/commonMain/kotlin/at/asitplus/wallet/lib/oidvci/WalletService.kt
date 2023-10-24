package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.CREDENTIAL_TYPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.datetime.Clock

/**
 * Client service to retrieve credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class WalletService(
    private val credentialScheme: ConstantIndex.CredentialScheme,
    private val credentialFormat: CredentialFormatEnum = CredentialFormatEnum.JWT_VC,
    /**
     * Pass names of attributes the credential shall contain, e.g. [at.asitplus.wallet.lib.iso.IsoDataModelConstants.DataElements]
     */
    private val requestedAttributes: Collection<String>? = null,
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val cryptoService: CryptoService = DefaultCryptoService(),
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
) {

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl])
     */
    fun createAuthRequest() = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        clientId = clientId,
        authorizationDetails = when (credentialScheme.credentialFormat) {
            ConstantIndex.CredentialFormat.ISO_18013 -> AuthorizationDetails(
                type = CREDENTIAL_TYPE_OPENID,
                format = CredentialFormatEnum.MSO_MDOC,
                docType = credentialScheme.isoDocType,
                types = arrayOf(credentialScheme.vcType),
                claims = buildIsoRequestedClaims()
            )

            ConstantIndex.CredentialFormat.W3C_VC -> AuthorizationDetails(
                type = CREDENTIAL_TYPE_OPENID,
                format = credentialFormat,
                types = arrayOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType,
            )
        },
        redirectUrl = redirectUrl,
    )

    /**
     * Send the result as POST parameters (form-encoded)to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl])
     */
    fun createTokenRequestParameters(code: String) = TokenRequestParameters(
        grantType = GRANT_TYPE_CODE,
        code = code,
        redirectUrl = redirectUrl,
        clientId = clientId,
    )

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     * Also send along the [TokenResponseParameters.accessToken] from [tokenResponse] in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     */
    suspend fun createCredentialRequest(
        tokenResponse: TokenResponseParameters,
        issuerMetadata: IssuerMetadata
    ): CredentialRequestParameters {
        // NOTE: Specification is missing a proof type for binding method `cose_key`, so we'll use JWT
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofTypes.JWT,
            jwt = jwsService.createSignedJwsAddingParams(
                header = JwsHeader(
                    algorithm = cryptoService.jwsAlgorithm,
                    type = OpenIdConstants.ProofTypes.JWT_HEADER_TYPE,
                ),
                payload = JsonWebToken(
                    issuer = clientId,
                    audience = issuerMetadata.credentialIssuer,
                    issuedAt = Clock.System.now(),
                    nonce = tokenResponse.clientNonce,
                ).serialize().encodeToByteArray(),
                addKeyId = true,
                addJsonWebKey = true
            )!!
        )
        return when (credentialScheme.credentialFormat) {
            ConstantIndex.CredentialFormat.ISO_18013 -> CredentialRequestParameters(
                format = CredentialFormatEnum.MSO_MDOC,
                docType = credentialScheme.isoDocType,
                claims = buildIsoRequestedClaims(),
                types = arrayOf(credentialScheme.vcType),
                proof = proof
            )

            ConstantIndex.CredentialFormat.W3C_VC -> CredentialRequestParameters(
                format = credentialFormat,
                claims = buildIsoRequestedClaims(),
                types = arrayOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType,
                proof = proof
            )
        }
    }

    private fun buildIsoRequestedClaims() = requestedAttributes?.let {
        mapOf(credentialScheme.isoNamespace to it.associateWith { RequestedCredentialClaimSpecification() })
    }

}