package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.RqesConstants
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import com.benasher44.uuid.uuid4

/**
 * Wallet service that implements generation of all data classes necessary
 * to successfully end-end a remote signature creation request by a driving application
 * This class focuses on the POTENTIAL UC5 wallet use case and
 * as such currently only supports `signHash`.
 * `signDoc` is out of testing scope for now but may be added later
 */
class RqesWalletService(
    private val clientId: String = "https://wallet.a-sit.at/app",
    redirectUrl: String = "$clientId/callback",
    stateToCodeStore: MapStore<String, String>? = null,
) {

    private val oauth2Client: OAuth2Client = OAuth2Client(
        clientId = clientId,
        redirectUrl = redirectUrl,
        stateToCodeStore = stateToCodeStore ?: DefaultMapStore()
    )

    suspend fun createOAuth2AuthenticationRequest(
        rqesRequest: SignatureRequestParameters,
        credentialId: ByteArray,
    ): AuthenticationRequestParameters =
        oauth2Client.createCscAuthnRequest(
            state = uuid4().toString(),
            authorizationDetails = setOf(rqesRequest.toAuthorizationDetails()),
            scope = RqesConstants.SCOPE,
            credentialId = credentialId,
        )

    suspend fun createOAuth2TokenRequest(
        state: String,
        authorization: OAuth2Client.AuthorizationForToken,
        authorizationDetails: Set<AuthorizationDetails>,
    ): TokenRequestParameters =
        oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = authorization,
            authorizationDetails = authorizationDetails,
        )


    suspend fun createSignHashRequestParameters(
        rqesRequest: SignatureRequestParameters,
        credentialId: String,
        sad: String,
    ): CscSignatureRequestParameters = SignHashParameters(
        credentialId = credentialId,
        sad = sad,
        hashes = rqesRequest.documentDigests.map { it.hash },
        signAlgoOid = X509SignatureAlgorithm.ES256.oid
    )

}

suspend fun OAuth2Client.createCscAuthnRequest(
    state: String,
    authorizationDetails: Set<AuthorizationDetails>? = null,
    scope: String? = null,
    requestUri: String? = null,
    credentialId: ByteArray? = null,
) = AuthenticationRequestParameters(
    responseType = GRANT_TYPE_CODE,
    state = state,
    clientId = clientId,
    authorizationDetails = authorizationDetails,
    scope = scope,
    redirectUrl = redirectUrl,
    codeChallenge = generateCodeVerifier(state),
    codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
    requestUri = requestUri,
    credentialID = credentialId
)