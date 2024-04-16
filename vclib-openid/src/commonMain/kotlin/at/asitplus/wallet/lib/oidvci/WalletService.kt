package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.cose.CborWebToken
import at.asitplus.crypto.datatypes.cose.CoseHeader
import at.asitplus.crypto.datatypes.cose.toCoseAlgorithm
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseParameters
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
    private val cryptoService: CryptoService = DefaultCryptoService(),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
    /**
     * Used to prove possession of the key material to create [CredentialRequestProof].
     */
    private val coseService: CoseService = DefaultCoseService(cryptoService),
) {

    private val stateToCodeChallengeMap = mutableMapOf<String, String>()
    private val codeChallengeMutex = Mutex()

    data class RequestOptions(
        /**
         * Credential type to request
         */
        val credentialScheme: ConstantIndex.CredentialScheme,
        /**
         * Required representation, see [ConstantIndex.CredentialRepresentation]
         */
        val representation: ConstantIndex.CredentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        /**
         * List of attributes that shall be requested explicitly (selective disclosure),
         * or `null` to make no restrictions
         */
        val requestedAttributes: List<String>? = null,
        /**
         * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
         */
        val state: String = uuid4().toString(),
    )

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl])
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createAuthRequest(
        requestOptions: RequestOptions,
        credentialIssuer: String? = null,
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = requestOptions.state,
        clientId = clientId,
        // TODO in authnrequest, and again in tokenrequest?
        authorizationDetails = requestOptions.representation.toAuthorizationDetails(
            requestOptions.credentialScheme,
            requestOptions.requestedAttributes
        ),
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(requestOptions.state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl]).
     *
     * @param scope Credential to request from the issuer, may be obtained from [IssuerMetadata.supportedCredentialConfigurations], or [SupportedCredentialFormat.scope].
     */
    suspend fun createAuthRequest(
        scope: String,
        credentialIssuer: String? = null,
        state: String = uuid4().toString()
    ) = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        state = state,
        clientId = clientId,
        scope = scope,
        resource = credentialIssuer,
        redirectUrl = redirectUrl,
        codeChallenge = generateCodeVerifier(state),
        codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    )

    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun generateCodeVerifier(state: String): String {
        val codeVerifier = Random.nextBytes(32).toHexString(HexFormat.Default)
        codeChallengeMutex.withLock { stateToCodeChallengeMap.put(state, codeVerifier) }
        return codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
    }

    /**
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl])
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createTokenRequestParameters(
        params: AuthenticationResponseParameters,
        requestOptions: RequestOptions,
    ) = TokenRequestParameters(
        grantType = GRANT_TYPE_CODE,
        code = params.code,
        redirectUrl = redirectUrl,
        clientId = clientId,
        // TODO in authnrequest, and again in tokenrequest?
        authorizationDetails = requestOptions.representation.toAuthorizationDetails(
            requestOptions.credentialScheme,
            requestOptions.requestedAttributes
        ),
        codeVerifier = codeChallengeMutex.withLock { stateToCodeChallengeMap.remove(params.state) }
    )

    /**
     * Send the result as POST parameters (form-encoded) to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl])
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createTokenRequestParameters(
        params: AuthenticationResponseParameters,
        credentialOffer: CredentialOffer,
        requestOptions: RequestOptions,
    ) = TokenRequestParameters(
        grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
        // TODO Verify if `redirect_uri` and `client_id` are even needed
        redirectUrl = redirectUrl,
        clientId = clientId,
        // TODO in authnrequest, and again in tokenrequest?
        authorizationDetails = requestOptions.representation.toAuthorizationDetails(
            requestOptions.credentialScheme,
            requestOptions.requestedAttributes
        ),
        transactionCode = credentialOffer.grants?.preAuthorizedCode?.transactionCode,
        preAuthorizedCode = credentialOffer.grants?.preAuthorizedCode?.preAuthorizedCode,
        codeVerifier = codeChallengeMutex.withLock { stateToCodeChallengeMap.remove(params.state) }
    )

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     * Also send along the [TokenResponseParameters.accessToken] from [tokenResponse] in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createCredentialRequestJwt(
        tokenResponse: TokenResponseParameters,
        issuerMetadata: IssuerMetadata,
        requestOptions: RequestOptions,
    ): KmmResult<CredentialRequestParameters> {
        val proofPayload = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = cryptoService.algorithm.toJwsAlgorithm(),
                type = OpenIdConstants.ProofTypes.JWT_HEADER_TYPE,
            ),
            payload = JsonWebToken(
                issuer = clientId,
                audience = issuerMetadata.credentialIssuer,
                issuedAt = Clock.System.now(),
                nonce = tokenResponse.clientNonce,
            ).serialize().encodeToByteArray(),
            addKeyId = false,
            addJsonWebKey = true
            // NOTE: use `x5c` to transport key attestation
        ).getOrElse {
            Napier.w("createCredentialRequestJwt: Error from jwsService: $it")
            return KmmResult.failure(it)
        }
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofTypes.JWT,
            jwt = proofPayload.serialize()
        )
        val result = requestOptions.representation.toCredentialRequestParameters(
            requestOptions.credentialScheme,
            requestOptions.requestedAttributes,
            proof
        )
        Napier.i("createCredentialRequestJwt returns $result")
        return KmmResult.success(result)
    }

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     * Also send along the [TokenResponseParameters.accessToken] from [tokenResponse] in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     *
     * @param requestOptions which credential in which representation to request
     */
    suspend fun createCredentialRequestCwt(
        tokenResponse: TokenResponseParameters,
        issuerMetadata: IssuerMetadata,
        requestOptions: RequestOptions,
    ): KmmResult<CredentialRequestParameters> {
        val proofPayload = coseService.createSignedCose(
            protectedHeader = CoseHeader(
                algorithm = cryptoService.algorithm.toCoseAlgorithm(),
                contentType = OpenIdConstants.ProofTypes.CWT_HEADER_TYPE,
                certificateChain = cryptoService.certificate?.encodeToDerOrNull()
            ),
            payload = CborWebToken(
                issuer = clientId,
                audience = issuerMetadata.credentialIssuer,
                issuedAt = Clock.System.now(),
                nonce = tokenResponse.clientNonce?.encodeToByteArray(),
            ).serialize()
        ).getOrElse {
            Napier.w("createCredentialRequestCwt: Error from coseService: $it")
            return KmmResult.failure(it)
        }
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofTypes.CWT,
            cwt = proofPayload.serialize().encodeToString(Base64UrlStrict),
        )
        val result = requestOptions.representation.toCredentialRequestParameters(
            requestOptions.credentialScheme,
            requestOptions.requestedAttributes,
            proof
        )
        Napier.i("createCredentialRequestCwt returns $result")
        return KmmResult.success(result)
    }

    private fun ConstantIndex.CredentialRepresentation.toAuthorizationDetails(
        credentialScheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Collection<String>?
    ) = when (this) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = toFormat(),
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, credentialScheme.vcType),
            ),
            claims = requestedAttributes?.toRequestedClaims(credentialScheme),
        )

        ConstantIndex.CredentialRepresentation.ISO_MDOC -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = toFormat(),
            docType = credentialScheme.isoDocType,
            claims = requestedAttributes?.toRequestedClaims(credentialScheme)
        )
    }

    private fun ConstantIndex.CredentialRepresentation.toCredentialRequestParameters(
        credentialScheme: ConstantIndex.CredentialScheme,
        requestedAttributes: Collection<String>?,
        proof: CredentialRequestProof
    ) = when (this) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialRequestParameters(
            format = toFormat(),
            claims = requestedAttributes?.toRequestedClaims(credentialScheme),
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType,
            ),
            proof = proof
        )

        ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialRequestParameters(
            format = toFormat(),
            docType = credentialScheme.isoDocType,
            claims = requestedAttributes?.toRequestedClaims(credentialScheme),
            proof = proof
        )
    }

    private fun Collection<String>.toRequestedClaims(credentialScheme: ConstantIndex.CredentialScheme) =
        mapOf(credentialScheme.isoNamespace to this.associateWith { RequestedCredentialClaimSpecification() })

}

private fun ConstantIndex.CredentialRepresentation.toFormat() = when (this) {
    ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialFormatEnum.VC_SD_JWT
    ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}
