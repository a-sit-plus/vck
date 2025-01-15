package at.asitplus.wallet.lib.rqes

import CscAuthorizationDetails
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.Hashes
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscDocumentDigest
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm.entries
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.pki.X509Certificate
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
    private val redirectUrl: String = "$clientId/callback",
    stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
) {
    data class SignatureProperties(
        val signatureQualifier: SignatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        val signatureFormat: SignatureFormat = SignatureFormat.PADES,
        val conformanceLevel: ConformanceLevel = ConformanceLevel.ADESBB,
        val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    )

    data class CryptoProperties(
        val signAlgorithm: X509SignatureAlgorithm = X509SignatureAlgorithm.ES256,
        val signAlgoParam: Asn1Element? = null,
    )

    data class SigningCredential(
        val credentialId: String,
        val certificates: List<X509Certificate>,
        val supportedSigningAlgorithms: List<X509SignatureAlgorithm>,
    )

    var signatureProperties = SignatureProperties()
        private set

    var cryptoProperties = CryptoProperties()
        private set

    //TODO check if [CryptoProperties] align with signingCredential otw change it
    var signingCredential: SigningCredential? = null
        private set

    private val oauth2Client: OAuth2Client = OAuth2Client(
        clientId = clientId,
        redirectUrl = redirectUrl,
        stateToCodeStore = stateToCodeStore
    )

    enum class RqesOauthScope(val value: String) {
        SERVICE("service"),
        CREDENTIAL("credential"),
    }

    /**
     * TODO probably match [SignatureProperties] and [CryptoProperties] with [credentialInfo] if they are set
     */
    suspend fun setSigningCredential(credentialInfo: CredentialInfo) {
        require(credentialInfo.credentialID != null)
        require(credentialInfo.certParameters != null)
        require(credentialInfo.certParameters!!.certificates != null)
        require(credentialInfo.certParameters!!.certificates!!.isNotEmpty())
        require(credentialInfo.certParameters!!.status == CscCertificateParameters.CertStatus.VALID)

        val signingAlgos =
            credentialInfo.keyParameters.algo.mapNotNull { oid -> catching { entries.first { it.oid == oid } }.getOrNull() }

        require(signingAlgos.isNotEmpty())

        signingCredential = SigningCredential(
            credentialId = credentialInfo.credentialID!!,
            certificates = credentialInfo.certParameters!!.certificates!!,
            supportedSigningAlgorithms = signingAlgos

        )
    }

    suspend fun updateSignaturePropoerties(
        signatureFormat: SignatureFormat? = null,
        conformanceLevel: ConformanceLevel? = null,
        signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    ) = signatureProperties.copy(
            signatureFormat = signatureFormat ?: signatureProperties.signatureFormat,
            conformanceLevel = conformanceLevel ?: signatureProperties.conformanceLevel,
            signedEnvelopeProperty = signedEnvelopeProperty ?: signatureProperties.signedEnvelopeProperty
        ).also {
            if (it.signedEnvelopeProperty?.viableSignatureFormats?.contains(it.signatureFormat) == false)
                throw IllegalArgumentException("Signed envelope property ${it.signedEnvelopeProperty} is not supported by signature format ${it.signatureFormat}")
            signatureProperties = it
        }

    suspend fun updateCryptoProperties(
        signAlgorithm: X509SignatureAlgorithm? = null,
        signAlgoParam: Asn1Element? = null,
    ) = cryptoProperties.copy(
        signAlgorithm = signAlgorithm ?: cryptoProperties.signAlgorithm,
        signAlgoParam = signAlgoParam ?: cryptoProperties.signAlgoParam
    ).also { cryptoProperties = it }

    suspend fun getCscAuthenticationDetails(
        /**
         * Here [OAuthDocumentDigest.hash] is the DTBS/R
         */
        documentDigests: Collection<OAuthDocumentDigest>,
    ): AuthorizationDetails =
        signingCredential?.let { signingCred ->
            CscAuthorizationDetails(
                credentialID = signingCred.credentialId,
                signatureQualifier = signatureProperties.signatureQualifier,
                hashAlgorithmOid = cryptoProperties.signAlgorithm.digest.oid,
                documentDigests = documentDigests
            )
        } ?: throw Exception("Please set a signing credential before using CSC functionality.")


    suspend fun getCscDocumentDigests(
        documentDigests: Collection<OAuthDocumentDigest>,
    ): CscDocumentDigest =
        CscDocumentDigest(
            hashes = documentDigests.map { it.hash },
            signatureFormat = signatureProperties.signatureFormat,
            conformanceLevel = signatureProperties.conformanceLevel,
            signAlgoOid = cryptoProperties.signAlgorithm.oid,
            signAlgoParams = cryptoProperties.signAlgoParam,
            signedEnvelopeProperty = signatureProperties.signedEnvelopeProperty
        )


    suspend fun createOAuth2AuthenticationRequest(
        scope: RqesOauthScope,
        redirectUrl: String = this.redirectUrl,
        authorizationDetails: Collection<AuthorizationDetails>? = null,
    ): AuthenticationRequestParameters =
        oauth2Client.createCscAuthnRequest(
            state = uuid4().toString(),
            authorizationDetails = authorizationDetails?.toSet(),
            scope = scope.value,
            redirectUrl = redirectUrl,
            credentialId = if (scope == RqesOauthScope.CREDENTIAL) signingCredential?.credentialId?.encodeToByteArray()
                ?: throw Exception("Please set a signing credential before using CSC functionality.") else null,
        )

    suspend fun createOAuth2TokenRequest(
        state: String,
        authorization: OAuth2Client.AuthorizationForToken,
        authorizationDetails: Set<AuthorizationDetails>? = null,
    ): TokenRequestParameters =
        oauth2Client.createTokenRequestParameters(
            state = state,
            authorization = authorization,
            authorizationDetails = authorizationDetails,
        )

    suspend fun createSignHashRequestParameters(
        dtbsr: Hashes,
        sad: String,
    ): CscSignatureRequestParameters = signingCredential?.credentialId?.let {
        SignHashParameters(
            credentialId = it,
            sad = sad,
            hashes = dtbsr,
            signAlgoOid = cryptoProperties.signAlgorithm.oid,
        )
    } ?: throw Exception("Please set a signing credential before using CSC functionality.")
}

suspend fun OAuth2Client.createCscAuthnRequest(
    state: String,
    authorizationDetails: Set<AuthorizationDetails>? = null,
    scope: String? = null,
    requestUri: String? = null,
    redirectUrl: String? = this.redirectUrl,
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