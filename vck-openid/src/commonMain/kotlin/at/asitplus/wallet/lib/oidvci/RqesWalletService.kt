package at.asitplus.wallet.lib.oidvci

import at.asitplus.dif.rqes.Enums.SignatureFormat
import at.asitplus.dif.rqes.RqesConstants
import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import at.asitplus.dif.rqes.SignatureRequestParameters
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.rqes.RqesRequest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import com.benasher44.uuid.uuid4

class RqesWalletService(
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val oauth2Client: OAuth2Client = OAuth2Client(clientId = clientId, redirectUrl = redirectUrl),
) {

    suspend fun createOAuth2AuthenticationRequest(
        rqesRequest: RqesRequest,
        credentialId: ByteArray,
    ): AuthenticationRequestParameters =
        oauth2Client.createAuthRequest(
            state = uuid4().toString(),
            authorizationDetails = setOf(rqesRequest.toAuthorizationDetails()),
            scope = RqesConstants.SCOPE,
            credentialId = credentialId,
        )

    /**
     * TODO: could also use [Document] instead of [CscDocumentDigest], also [credential_id] instead of [SAD]
     */
    suspend fun createSignDocRequestParameters(rqesRequest: RqesRequest, sad: String): SignatureRequestParameters =
        SignDocParameters(
            sad = sad,
            signatureQualifier = rqesRequest.signatureQualifier,
            documentDigests = listOf(
                rqesRequest.getCscDocumentDigests(
                    signatureFormat = SignatureFormat.CADES,
                    signAlgorithm = X509SignatureAlgorithm.ES256,
                )
            ),
            responseUri = this.redirectUrl, //TODO double check
        )

    suspend fun createSignHashRequestParameters(
        rqesRequest: RqesRequest,
        credentialId: String,
        sad: String,
    ): SignatureRequestParameters = SignHashParameters(
        credentialId = credentialId,
        sad = sad,
        hashes = rqesRequest.documentDigests.map { it.hash }
    )

}

