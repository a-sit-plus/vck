package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.CscAuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.RqesConstants
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import com.benasher44.uuid.uuid4

class RqesWalletService(
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    val oauth2Client: OAuth2Client = OAuth2Client(clientId = clientId, redirectUrl = redirectUrl),
) {

    suspend fun createOAuth2AuthenticationRequest(
        rqesRequest: SignatureRequestParameters,
        credentialId: ByteArray,
    ): CscAuthenticationRequestParameters =
        oauth2Client.createCscAuthnRequest(
            state = uuid4().toString(),
            authorizationDetails = setOf(rqesRequest.toAuthorizationDetails()),
            scope = RqesConstants.SCOPE,
            credentialId = credentialId,
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
) = CscAuthenticationRequestParameters(
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