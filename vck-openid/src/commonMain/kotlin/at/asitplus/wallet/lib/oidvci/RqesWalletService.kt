package at.asitplus.wallet.lib.oidvci

import at.asitplus.dif.rqes.CSCSignatureRequestParameters
import at.asitplus.dif.rqes.enums.SignatureFormat
import at.asitplus.dif.rqes.RqesConstants
import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.SignatureRequestParameters
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import com.benasher44.uuid.uuid4

class RqesWalletService(
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val oauth2Client: OAuth2Client = OAuth2Client(clientId = clientId, redirectUrl = redirectUrl),
) {

    suspend fun createOAuth2AuthenticationRequest(
        rqesRequest: SignatureRequestParameters,
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
    suspend fun createSignDocRequestParameters(rqesRequest: SignatureRequestParameters, sad: String): CSCSignatureRequestParameters =
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
        rqesRequest: SignatureRequestParameters,
        credentialId: String,
        sad: String,
    ): CSCSignatureRequestParameters = SignHashParameters(
        credentialId = credentialId,
        sad = sad,
        hashes = rqesRequest.documentDigests.map { it.hash },
        signAlgoOid = X509SignatureAlgorithm.ES256.oid
    )

}

