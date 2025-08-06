package at.asitplus.wallet.lib.rqes

import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.csc.CredentialInfo
import at.asitplus.openid.CscAuthorizationDetails
import at.asitplus.csc.Hashes
import at.asitplus.csc.QtspSignatureRequest
import at.asitplus.csc.SignHashRequestParameters
import at.asitplus.csc.collection_entries.*
import at.asitplus.csc.enums.ConformanceLevel
import at.asitplus.csc.enums.SignatureFormat
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.csc.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm.Companion.entries
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.rqes.helper.OAuth2RqesParameters
import com.benasher44.uuid.uuid4

/**
 * Wallet service that implements generation of all data classes necessary
 * to successfully end-end a remote signature creation request by a driving application
 * This class focuses on the POTENTIAL UC5 wallet use case and
 * as such currently only supports `signHash`.
 * `signDoc` is out of testing scope for now but may be added later
 */
class RqesOpenId4VpHolder(
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val oauth2Client: OAuth2Client = OAuth2Client(
        clientId = clientId,
        redirectUrl = redirectUrl,
    ),
) {
    data class SignatureProperties(
        val signatureQualifier: SignatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        val signatureFormat: SignatureFormat = SignatureFormat.PADES,
        val conformanceLevel: ConformanceLevel = ConformanceLevel.ADESBB,
        val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    )

    data class SigningCredential(
        val credentialId: String,
        val certificates: List<X509Certificate>,
        val supportedSigningAlgorithms: List<X509SignatureAlgorithm>,
    )

    var signatureProperties = SignatureProperties()
        private set

    var signingCredential: SigningCredential? = null
        private set

    enum class RqesOauthScope(val value: String) {
        SERVICE("service"),
        CREDENTIAL("credential"),
    }

    @Throws(IllegalArgumentException::class)
    fun setSigningCredential(credentialInfo: CredentialInfo) {
        require(credentialInfo.credentialID != null) {
            "credentialID must not be null (Required by SignHashRequestParameters)"
        }

        with(credentialInfo.certParameters) {
            require(this != null) { "Certificate parameters must not be null" }
            require(!this.certificates.isNullOrEmpty()) { "Signing Certificate chain must not be null or empty" }
            this.status?.let { status ->
                require(status == CertificateParameters.CertStatus.VALID) { "Signing Certificate status must be valid" }
            }
        }

        with(credentialInfo.keyParameters) {
            require(status == KeyParameters.KeyStatusOptions.ENABLED) { "Signing key parameters must be enabled" }
        }

        val signingAlgos = credentialInfo.keyParameters.algo
            .mapNotNull { oid -> catching { entries.first { it.oid == oid } }.getOrNull() }

        require(signingAlgos.isNotEmpty()) { "Supported signing algorithms must not be null or empty" }

        signingCredential = SigningCredential(
            credentialId = credentialInfo.credentialID!!,
            certificates = credentialInfo.certParameters!!.certificates!!,
            supportedSigningAlgorithms = signingAlgos,
        )
    }

    suspend fun updateSignatureProperties(
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

    /**
     * Here [OAuthDocumentDigest.hash] is the DTBS/R and will be hashed again with [hashAlgorithmOid]
     */
    suspend fun getCscAuthenticationDetails(
        documentDigests: Collection<OAuthDocumentDigest>,
        hashAlgorithm: Digest,
        documentLocation: Collection<DocumentLocation>? = null,
    ): AuthorizationDetails = signingCredential?.let { signingCred ->
        CscAuthorizationDetails(
            credentialID = signingCred.credentialId,
            signatureQualifier = signatureProperties.signatureQualifier,
            hashAlgorithmOid = hashAlgorithm.oid,
            documentDigests = documentDigests,
            documentLocations = documentLocation
        )
    } ?: throw Exception("Please set a signing credential before using CSC functionality.")

    suspend fun getCscDocumentDigests(
        documentDigests: Collection<OAuthDocumentDigest>,
        signatureAlgorithm: X509SignatureAlgorithm,
    ): DocumentDigest = DocumentDigest(
        hashes = documentDigests.map { it.hash },
        signatureFormat = signatureProperties.signatureFormat,
        conformanceLevel = signatureProperties.conformanceLevel,
        signAlgoOid = signatureAlgorithm.oid,
        signedEnvelopeProperty = signatureProperties.signedEnvelopeProperty
    )

    /**
     * CSC API v2.0.0.2
     * Authorization to access `/credentials/info` and `/credentials/list` endpoints
     */
    suspend fun createServiceAuthenticationRequest(
        redirectUrl: String = this.redirectUrl,
        wrapAsPar: Boolean = false,
        optionalParameters: OAuth2RqesParameters.Optional? = null,
    ): AuthenticationRequestParameters = oauth2Client.createAuthRequest(
        state = uuid4().toString(),
        scope = RqesOauthScope.SERVICE.value,
        wrapAsJar = wrapAsPar,
    ).enrichAuthRequest(
        redirectUrl = redirectUrl,
        optionalParameters = optionalParameters
    )

    /**
     * CSC API v2.0.0.2
     * Authorization to access `/credentials/signHash` and `/credentials/signDoc` endpoints
     */
    suspend fun createCredentialAuthenticationRequest(
        documentDigests: Collection<OAuthDocumentDigest>,
        redirectUrl: String = this.redirectUrl,
        hashAlgorithm: Digest,
        wrapAsPar: Boolean = false,
        optionalParameters: OAuth2RqesParameters.Optional? = null,
        documentLocation: Collection<DocumentLocation>? = null,
    ): AuthenticationRequestParameters = oauth2Client.createAuthRequest(
        state = uuid4().toString(),
        authorizationDetails = setOf(getCscAuthenticationDetails(documentDigests, hashAlgorithm, documentLocation)),
        wrapAsJar = wrapAsPar,
    ).enrichAuthRequest(
        redirectUrl = redirectUrl,
        optionalParameters = optionalParameters
    )

    suspend fun createOAuth2TokenRequest(
        state: String,
        authorization: OAuth2Client.AuthorizationForToken,
        authorizationDetails: Set<AuthorizationDetails>? = null,
    ): TokenRequestParameters = oauth2Client.createTokenRequestParameters(
        state = state,
        authorization = authorization,
        authorizationDetails = authorizationDetails,
    )

    suspend fun createSignHashRequestParameters(
        dtbsr: Hashes,
        sad: String,
        signatureAlgorithm: X509SignatureAlgorithm,
    ): QtspSignatureRequest = signingCredential?.let {
        require(it.supportedSigningAlgorithms.contains(signatureAlgorithm))
        SignHashRequestParameters(
            credentialId = it.credentialId,
            sad = sad,
            hashes = dtbsr,
            signAlgoOid = signatureAlgorithm.oid,
        )
    } ?: throw Exception("Please set a signing credential before using CSC functionality.")
}

private suspend fun AuthenticationRequestParameters.enrichAuthRequest(
    redirectUrl: String?,
    requiredParameters: OAuth2RqesParameters.CredentialRequired? = null,
    optionalParameters: OAuth2RqesParameters.Optional? = null,
): AuthenticationRequestParameters = this.copy(
    redirectUrl = redirectUrl,
    lang = optionalParameters?.lang,
    credentialID = requiredParameters?.credentialID,
    signatureQualifier = requiredParameters?.signatureQualifier,
    numSignatures = requiredParameters?.numSignatures,
    hashes = requiredParameters?.hashes,
    hashAlgorithmOid = requiredParameters?.hashAlgorithmOid,
    description = optionalParameters?.description,
    accountToken = optionalParameters?.accountToken,
    clientData = optionalParameters?.clientData,
)