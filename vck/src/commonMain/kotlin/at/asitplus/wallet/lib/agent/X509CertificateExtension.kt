package at.asitplus.wallet.lib.agent


import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import io.github.aakira.napier.Napier
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlin.time.Clock

suspend fun Certificate.Companion.generateSelfSignedCertificate(
    publicKey: CryptoPublicKey,
    algorithm: SignatureAlgorithm,
    lifetimeInSeconds: Long = 30,
    extensions: List<CertificateExtension> = listOf(),
    signer: suspend (ByteArray) -> KmmResult<CryptoSignature>,
): KmmResult<Certificate> = catching {
    Napier.d { "Generating self-signed Certificate" }
    val notBeforeDate = Clock.System.now().truncateToSeconds()
    val notAfterDate = notBeforeDate.plus(lifetimeInSeconds, DateTimeUnit.SECOND)
    val name = X500Name(RelativeDistinguishedName(X500AttributeTypeAndValue.CommonName("Default")))
    val tbsCertificate = TbsCertificate(
        serialNumber = Asn1Integer.ONE,
        issuerName = name,
        subjectName = name,
        validFrom = notBeforeDate,
        validUntil = notAfterDate,
        signatureAlgorithm = algorithm,
        publicKey = publicKey,
        extensions = extensions,
    )

    signer(tbsCertificate.encodeToDer()).map { signature ->
        Certificate(tbsCertificate, signature)
    }.getOrThrow()

}