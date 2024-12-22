package at.asitplus.wallet.lib.rqes

import CscAuthorizationDetails
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.OpenIdConstants.CODE_CHALLENGE_METHOD_SHA256
import at.asitplus.openid.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.SignatureRequestParameters
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscDocumentDigest
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.wallet.lib.iso.sha256
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
    /**
     * Way to transform hashes received from DA to DTBS/R which is needed for all actions in connection with CSC
     * Need [CredentialInfo] of certificate that the QTSP associates with the Wallet and which will be used for signing
     */
    private val dtbsrBuilder: (OAuthDocumentDigest, CredentialInfo) -> OAuthDocumentDigest,
    redirectUrl: String = "$clientId/callback",
    stateToCodeStore: MapStore<String, String> = DefaultMapStore(),
) {
    /**
     * Initialized to common parameters
     */
    private object SignatureProperties {
        val signatureQualifier: SignatureQualifier = SignatureQualifier.EU_EIDAS_QES
        var signatureFormat: SignatureFormat = SignatureFormat.PADES
        var conformanceLevel: ConformanceLevel = ConformanceLevel.ADESBB
        var signedEnvelopeProperty: SignedEnvelopeProperty? = null
    }

    /**
     * Initialized to common parameters
     */
    private object CryptoProperties {
        var signAlgorithm: X509SignatureAlgorithm = X509SignatureAlgorithm.ES256
        var signAlgoParam: Asn1Element? = null
        var hashAlgorithm: Digest = signAlgorithm.digest
    }

    private var credentialInfo: CredentialInfo? = null

    val oauth2Client: OAuth2Client = OAuth2Client(
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
        this.credentialInfo = credentialInfo
    }

    suspend fun updateSignaturePropoerties(
        signatureFormat: SignatureFormat? = null,
        conformanceLevel: ConformanceLevel? = null,
        signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    ) {
        with(SignatureProperties) {
            this.signatureFormat = signatureFormat ?: this.signatureFormat
            this.conformanceLevel = conformanceLevel ?: this.conformanceLevel
            this.signedEnvelopeProperty = signedEnvelopeProperty ?: this.signedEnvelopeProperty
            if (this.signedEnvelopeProperty?.viableSignatureFormats?.contains(this.signatureFormat) == false) throw IllegalArgumentException(
                "Signed envelope property ${this.signedEnvelopeProperty} is not supported by signature format ${this.signatureFormat}"
            )
        }
    }

    suspend fun updateCryptoProperties(
        signAlgorithm: X509SignatureAlgorithm? = null,
        signAlgoParam: Asn1Element? = null,
        hashAlgorithm: Digest? = null,
    ) {
        with(CryptoProperties) {
            this.signAlgorithm = signAlgorithm ?: this.signAlgorithm
            this.signAlgoParam = signAlgoParam ?: this.signAlgoParam
            this.hashAlgorithm = hashAlgorithm ?: this.hashAlgorithm
            if (this.signAlgorithm.digest != hashAlgorithm) throw IllegalArgumentException("SignAlgorithm ${this.signAlgorithm::class.simpleName} does not use digest ${this.hashAlgorithm::class.simpleName}!")
        }
    }

    suspend fun getCscAuthenticationDetails(
        signatureRequestParameters: SignatureRequestParameters,
    ): AuthorizationDetails =
        credentialInfo?.let { credInfo ->
            require(signatureRequestParameters.signatureQualifier == SignatureProperties.signatureQualifier)
            require(signatureRequestParameters.hashAlgorithm == CryptoProperties.hashAlgorithm)
            CscAuthorizationDetails(
                credentialID = credInfo.credentialID!!,
                signatureQualifier = signatureRequestParameters.signatureQualifier,
                hashAlgorithmOid = signatureRequestParameters.hashAlgorithmOid,
                documentDigests = signatureRequestParameters.documentDigests.onEach {
                    dtbsrBuilder(
                        it,
                        credInfo
                    )
                },
                documentLocations = signatureRequestParameters.documentLocations,
            )
        } ?: throw Exception("Please set a signing credential before using CSC functionality.")


    suspend fun getCscDocumentDigests(
        documentDigests: Collection<OAuthDocumentDigest>,
    ): CscDocumentDigest =
        CscDocumentDigest(
            hashes = documentDigests.map { it.hash },
            hashAlgorithmOid = CryptoProperties.hashAlgorithm.oid,
            signatureFormat = SignatureProperties.signatureFormat,
            conformanceLevel = SignatureProperties.conformanceLevel,
            signAlgoOid = CryptoProperties.signAlgorithm.oid,
            signAlgoParams = CryptoProperties.signAlgoParam,
            signedEnvelopeProperty = SignatureProperties.signedEnvelopeProperty
        )


    suspend fun createOAuth2AuthenticationRequest(
        scope: RqesOauthScope,
        authorizationDetails: Collection<AuthorizationDetails>? = null,
        setCredentialId: Boolean,
    ): AuthenticationRequestParameters =
        oauth2Client.createCscAuthnRequest(
            state = uuid4().toString(),
            authorizationDetails = authorizationDetails?.toSet(),
            scope = scope.value,
            credentialId = if (setCredentialId) credentialInfo?.credentialID?.encodeToByteArray()
                ?: throw Exception("Please set a signing credential before using CSC functionality.") else null,
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
        dtbsr: Collection<ByteArray>,
        sad: String,
    ): CscSignatureRequestParameters = credentialInfo?.credentialID?.let {
        SignHashParameters(
            credentialId = it,
            sad = sad,
            hashes = dtbsr.map { it.sha256() },
            signAlgoOid = CryptoProperties.signAlgorithm.oid,
        )
    } ?: throw Exception("Please set a signing credential before using CSC functionality.")
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