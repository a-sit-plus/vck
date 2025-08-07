package io.kotest.provided.at.asitplus.wallet.lib.rqes.helper

import at.asitplus.csc.CredentialInfo
import at.asitplus.csc.collection_entries.*
import at.asitplus.csc.enums.SignatureQualifier
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
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
        authParameters = AuthParameters(
            mode = AuthParameters.AuthMode.EXPLICIT,
        ),
        scal = CredentialInfo.ScalOptions.entries.random(),
        multisign = 1U,
        lang = "de"
    )

    private suspend fun cscCertificateParameters(isValid: Boolean) = CertificateParameters(
        status = if (isValid) CertificateParameters.CertStatus.VALID else CertificateParameters.CertStatus.entries.random(),
        certificates = listOf(EphemeralKeyWithSelfSignedCert().getCertificate()!!),
        issuerDN = uuid4().toString(),
        serialNumber = uuid4().toString(),
        subjectDN = uuid4().toString(),
    )

    private fun X509SignatureAlgorithm.toCscKeyParameters(
        isValid: Boolean,
    ): KeyParameters = KeyParameters(
        status = if (isValid) KeyParameters.KeyStatusOptions.ENABLED else KeyParameters.KeyStatusOptions.entries.random(),
        algo = setOf(oid),
        len = digest.outputLength.bits,
        curve = if (isEc) (algorithm.toJwsAlgorithm().getOrThrow() as JwsAlgorithm.Signature.EC).ecCurve.oid else null
    )

    fun buildDocumentDigests(): List<OAuthDocumentDigest> = (1..Random.nextInt(10)).map {
        OAuthDocumentDigest(
            hash = uuid4().bytes.encodeToString(Base64UrlStrict).decodeToByteArray(Base64UrlStrict),
            label = uuid4().toString(),
        )
    }
}

val X509SignatureAlgorithm.digest: Digest
    get() = when (this) {
        is X509SignatureAlgorithm.ECDSA -> digest
        is X509SignatureAlgorithm.RSAPSS -> digest
        is X509SignatureAlgorithm.RSAPKCS1 -> digest
    }