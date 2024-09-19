package at.asitplus.wallet.lib.oidvci

import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.Enums.SignatureQualifierEnum
import at.asitplus.dif.rqes.RqesConstants
import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import at.asitplus.dif.rqes.SignatureRequestParameters
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialRequestProof
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.rqes.RqesRequest
import at.asitplus.signum.indispensable.asn1.KnownOIDs.ecdsaWithSHA256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidvci.WalletService.AuthorizationForToken
import com.benasher44.uuid.uuid4
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random

class RqesWalletService(
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
    private val stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
) {
    @OptIn(ExperimentalStdlibApi::class)
    private suspend fun generateCodeVerifier(state: String): String {
        val codeVerifier = Random.nextBytes(32).toHexString(HexFormat.Default)
        stateToCodeStore.put(state, codeVerifier)
        return codeVerifier.encodeToByteArray().sha256().encodeToString(Base64UrlStrict)
    }

    /**
     * CSC: Minimal implementation for CSC requests
     */
    suspend fun createOAuth2AuthRequest(
        rqesRequest: RqesRequest,
        credentialIssuer: String? = null,
        requestUri: String? = null,
    ) = createOAuth2AuthRequest(
        state = rqesRequest.state ?: uuid4().toString(),
        authorizationDetails = rqesRequest.toAuthorizationDetails(),
        credentialIssuer = credentialIssuer,
        requestUri = requestUri,
    )

    /**
     * CSC: Minimal implementation for CSC requests
     */
    suspend fun createOAuth2AuthRequest(
        state: String,
        authorizationDetails: AuthorizationDetails,
        credentialIssuer: String? = null,
        requestUri: String? = null,
    ): AuthenticationRequestParameters = when (authorizationDetails) {
        is AuthorizationDetails.OpenIdCredential -> AuthenticationRequestParameters(
            responseType = GRANT_TYPE_CODE,
            state = state,
            clientId = clientId,
            authorizationDetails = setOf(authorizationDetails),
            resource = credentialIssuer,
            redirectUrl = redirectUrl,
            codeChallenge = generateCodeVerifier(state),
            codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
        )

        is AuthorizationDetails.CSCCredential -> AuthenticationRequestParameters(
            responseType = GRANT_TYPE_CODE,
            state = state,
            clientId = clientId,
            authorizationDetails = setOf(authorizationDetails),
            scope = RqesConstants.SCOPE,
            redirectUrl = redirectUrl,
            codeChallenge = generateCodeVerifier(state),
            codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
            requestUri = requestUri
        )
    }


    /**
     * CSC: Minimal implementation for CSC requests.
     */
    suspend fun createOauth2TokenRequestParameters(
        state: String,
        authorizationDetails: Set<AuthorizationDetails>,
        authorization: AuthorizationForToken,
    ) = when (authorization) {
        is AuthorizationForToken.Code -> TokenRequestParameters(
            grantType = GRANT_TYPE_AUTHORIZATION_CODE,
            code = authorization.code,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = authorizationDetails,
            codeVerifier = stateToCodeStore.remove(state)
        )

        is AuthorizationForToken.PreAuthCode -> TokenRequestParameters(
            grantType = GRANT_TYPE_PRE_AUTHORIZED_CODE,
            redirectUrl = redirectUrl,
            clientId = clientId,
            authorizationDetails = authorizationDetails,
            transactionCode = authorization.preAuth.transactionCode,
            preAuthorizedCode = authorization.preAuth.preAuthorizedCode,
            codeVerifier = stateToCodeStore.remove(state)
        )
    }

    /**
     * TODO: could also use [Document] instead of [CscDocumentDigest], also [credential_id] instead of [SAD]
     */
    suspend fun createSignDocRequestParameters(rqesRequest: RqesRequest, sad: String): SignatureRequestParameters = SignDocParameters(
        sad = sad,
        signatureQualifier = rqesRequest.signatureQualifier,
        documentDigests = listOf(rqesRequest.getCscDocumentDigests(
            signatureFormat = SignatureFormat.CADES,
            signAlgorithm = ecdsaWithSHA256,
        )),
        responseUri = this.redirectUrl, //TODO double check
    )

    suspend fun createSignHashRequestParameters(rqesRequest: RqesRequest, credentialId: String, sad: String): SignatureRequestParameters = SignHashParameters(
        credentialId = credentialId,
        sad = sad,
        hashes = rqesRequest.documentDigests.map { it.hash }
    )

}

