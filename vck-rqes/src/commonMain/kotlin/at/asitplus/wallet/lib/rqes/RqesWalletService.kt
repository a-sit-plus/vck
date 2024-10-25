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

    //TODO see below
//    suspend fun createOAuth2AuthenticationRequest(
//        rqesRequest: SignatureRequestParameters,
//        credentialId: ByteArray,
//    ): AuthenticationRequestParameters =
//        oauth2Client.createAuthRequest(
//            state = uuid4().toString(),
//            authorizationDetails = setOf(rqesRequest.toAuthorizationDetails()),
//            scope = RqesConstants.SCOPE,
//            credentialId = credentialId,
//        )

    /**
     * TODO: could also use [Document] instead of [CscDocumentDigest], also [credential_id] instead of [SAD]
     * TODO implement [CredentialInfo] dataclass + hand over here
     */
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
            responseUri = this.redirectUrl, //TODO double check
        )


    //TODO implement [CredentialInfo] dataclass + hand over here
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

//TODO find way to incorperate this
//suspend fun OAuth2Client.createCscAuthnRequest(
//    state: String,
//    authorizationDetails: Set<AuthorizationDetails>? = null,
//    scope: String? = null,
//    requestUri: String? = null,
//    credentialId: ByteArray? = null,
//) = CscAuthenticationRequestParameters(
//    responseType = GRANT_TYPE_CODE,
//    state = state,
//    clientId = clientId,
//    authorizationDetails = authorizationDetails,
//    scope = scope,
//    redirectUrl = redirectUrl,
//    codeChallenge = generateCodeVerifier(state),
//    codeChallengeMethod = CODE_CHALLENGE_METHOD_SHA256,
//    requestUri = requestUri,
//    credentialID = credentialId
//)

