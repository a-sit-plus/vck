package at.asitplus.wallet.lib.rqes

import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.SignDocParameters
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.wallet.lib.oauth2.OAuth2Client

class RqesWalletService(
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val oauth2Client: OAuth2Client = OAuth2Client(clientId = clientId, redirectUrl = redirectUrl),
) {
    suspend fun createSignDocRequestParameters(
        rqesRequest: SignatureRequestParameters,
        sad: String,
    ): CscSignatureRequestParameters =
        SignDocParameters(
            sad = sad,
            signatureQualifier = rqesRequest.signatureQualifier,
            documentDigests = listOf(
                rqesRequest.getCscDocumentDigests(
                    signatureFormat = SignatureFormat.CADES,
                    signAlgorithm = X509SignatureAlgorithm.ES256,
                )
            ),
            responseUri = this.redirectUrl,
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