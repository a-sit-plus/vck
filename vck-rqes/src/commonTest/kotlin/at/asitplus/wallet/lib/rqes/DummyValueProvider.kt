package at.asitplus.wallet.lib.rqes

import at.asitplus.openid.SignatureQualifier
import at.asitplus.rqes.CredentialInfo
import at.asitplus.rqes.collection_entries.CscAuthParameter
import at.asitplus.rqes.collection_entries.CscCertificateParameters
import at.asitplus.rqes.collection_entries.CscKeyParameters
import at.asitplus.rqes.collection_entries.OAuthDocumentDigest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import com.benasher44.uuid.bytes
import com.benasher44.uuid.uuid4
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.random.Random


class DummyValueProvider {

    val validSignatureAlgorithms = listOf(
        X509SignatureAlgorithm.RS256,
        X509SignatureAlgorithm.RS384,
        X509SignatureAlgorithm.RS512,
        X509SignatureAlgorithm.ES256,
        X509SignatureAlgorithm.ES384,
        X509SignatureAlgorithm.ES512,
    )

    suspend fun getSigningCredential(isValid: Boolean = false): CredentialInfo = CredentialInfo(
        credentialID = uuid4().toString(),
        signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
        keyParameters = validSignatureAlgorithms.random().toCscKeyParameters(isValid),
        certParameters = cscCertificateParameters(isValid),
        authParameters = CscAuthParameter(
            mode = CscAuthParameter.AuthMode.EXPLICIT,
        ),
        scal = CredentialInfo.ScalOptions.entries.random(),
        multisign = 1U,
        lang = "de"
    )

    private suspend fun cscCertificateParameters(isValid: Boolean) = CscCertificateParameters(
        status = if (isValid) CscCertificateParameters.CertStatus.VALID else CscCertificateParameters.CertStatus.entries.random(),
        certificates = listOf(EphemeralKeyWithSelfSignedCert().getCertificate()!!),
        issuerDN = uuid4().toString(),
        serialNumber = uuid4().toString(),
        subjectDN = uuid4().toString(),
    )

    private fun X509SignatureAlgorithm.toCscKeyParameters(
        isValid: Boolean,
    ): CscKeyParameters = CscKeyParameters(
        status = if (isValid) CscKeyParameters.KeyStatusOptions.ENABLED else CscKeyParameters.KeyStatusOptions.entries.random(),
        algo = listOf(oid),
        len = digest.outputLength.bits,
        curve = if (isEc) algorithm.toJwsAlgorithm().getOrThrow().ecCurve!!.oid else null
    )

    fun buildDocumentDigests(): List<OAuthDocumentDigest> = (1..Random.nextInt(10)).map {
        OAuthDocumentDigest(
            hash = uuid4().bytes.encodeToString(Base64UrlStrict).decodeToByteArray(Base64UrlStrict),
            label = uuid4().toString(),
        )
    }
}