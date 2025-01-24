package at.asitplus.wallet.lib.rqes

import CscAuthorizationDetails
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.Hashes
import at.asitplus.openid.SignatureQualifier
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.CscSignatureRequestParameters
import at.asitplus.rqes.SignHashParameters
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscDocumentDigest
import at.asitplus.rqes.collection_entries.CscKeyParameters
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.rqes.enums.ConformanceLevel
import at.asitplus.rqes.enums.SignatureFormat
import at.asitplus.rqes.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm.entries
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.DefaultMapStore
import at.asitplus.wallet.lib.oidvci.MapStore
import at.asitplus.wallet.lib.rqes.helper.OAuth2RqesParameters
import com.benasher44.uuid.uuid4
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

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

    data class SigningCredential(
        val credentialId: String,
        val certificates: List<X509Certificate>,
        val supportedSigningAlgorithms: List<X509SignatureAlgorithm>,
    )

    var signatureProperties = SignatureProperties()
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
        with(credentialInfo.certParameters!!) {
            require(!this.certificates.isNullOrEmpty())
            require(this.status == CscCertificateParameters.CertStatus.VALID)
        }

        with(credentialInfo.keyParameters) {
            require(status == CscKeyParameters.KeyStatusOptions.ENABLED)
        }

        val signingAlgos =
            credentialInfo.keyParameters.algo.mapNotNull { oid -> catching { entries.first { it.oid == oid } }.getOrNull() }

        require(signingAlgos.isNotEmpty())

        signingCredential = SigningCredential(
            credentialId = credentialInfo.credentialID!!,
            certificates = credentialInfo.certParameters!!.certificates!!,
            supportedSigningAlgorithms = signingAlgos,
        )
    }

    @Suppress("unused")
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

    /**
     * Here [OAuthDocumentDigest.hash] is the DTBS/R and will be hashed again with [hashAlgorithmOid]
     */
    suspend fun getCscAuthenticationDetails(
        documentDigests: Collection<OAuthDocumentDigest>,
        hashAlgorithm: Digest,
    ): AuthorizationDetails =
        signingCredential?.let { signingCred ->
            CscAuthorizationDetails(
                credentialID = signingCred.credentialId,
                signatureQualifier = signatureProperties.signatureQualifier,
                hashAlgorithmOid = hashAlgorithm.oid,
                documentDigests = documentDigests
            )
        } ?: throw Exception("Please set a signing credential before using CSC functionality.")


    suspend fun getCscDocumentDigests(
        documentDigests: Collection<OAuthDocumentDigest>,
        signatureAlgorithm: X509SignatureAlgorithm,
    ): CscDocumentDigest =
        CscDocumentDigest(
            hashes = documentDigests.map { it.hash },
            signatureFormat = signatureProperties.signatureFormat,
            conformanceLevel = signatureProperties.conformanceLevel,
            signAlgoOid = signatureAlgorithm.oid,
            signedEnvelopeProperty = signatureProperties.signedEnvelopeProperty
        )

    suspend fun createServiceAuthenticationRequest(
        redirectUrl: String = this.redirectUrl,
        optionalParameters: OAuth2RqesParameters.Optional? = null,
    ): AuthenticationRequestParameters =
        oauth2Client.createAuthRequest(
            state = uuid4().toString(),
            scope = RqesOauthScope.SERVICE.value,
        ).enrichAuthRequest(
            redirectUrl = redirectUrl,
            optionalParameters = optionalParameters
        )

    suspend fun createCredentialAuthenticationRequest(
        documentDigests: Collection<OAuthDocumentDigest>,
        redirectUrl: String = this.redirectUrl,
        hashAlgorithm: Digest,
        numSignatures: Int,
        hashes: Hashes,
        optionalParameters: OAuth2RqesParameters.Optional? = null,
    ): AuthenticationRequestParameters =
        oauth2Client.createAuthRequest(
            state = uuid4().toString(),
            authorizationDetails = setOf(getCscAuthenticationDetails(documentDigests, hashAlgorithm)),
            scope = RqesOauthScope.CREDENTIAL.value,
        ).enrichAuthRequest(
            redirectUrl = redirectUrl,
            requiredParameters = OAuth2RqesParameters.CredentialRequired(
                credentialID = signingCredential?.credentialId?.decodeToByteArray(Base64UrlStrict)
                    ?: throw Exception("Please set a signing credential before using CSC functionality."),
                signatureQualifier = signatureProperties.signatureQualifier,
                numSignatures = numSignatures,
                hashes = hashes,
                hashAlgorithmOid = hashAlgorithm.oid,
            ),
            optionalParameters = optionalParameters
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
        signatureAlgorithm: X509SignatureAlgorithm,
    ): CscSignatureRequestParameters = signingCredential?.let {
        require(it.supportedSigningAlgorithms.contains(signatureAlgorithm))
        SignHashParameters(
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
): AuthenticationRequestParameters =
    this.copy(
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