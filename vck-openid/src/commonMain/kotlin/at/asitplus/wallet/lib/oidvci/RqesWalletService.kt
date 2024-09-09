package at.asitplus.wallet.lib.oidvci

import at.asitplus.dif.rqes.RqesConstants
import at.asitplus.dif.rqes.SignatureRequestParameters
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CredentialRequestProof
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_AUTHORIZATION_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.oidvci.WalletService.AuthorizationForToken
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
    suspend fun createAuthRequest(
        state: String,
        authorizationDetails: AuthorizationDetails,
        credentialIssuer: String? = null,
        requestUri: String? = null,
    ): AuthenticationRequestParameters =
        when (authorizationDetails) {
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

    suspend fun createSignDocRequestParameters(): SignatureRequestParameters = TODO()

    suspend fun createSignHashRequestParameters(): SignatureRequestParameters = TODO()

}