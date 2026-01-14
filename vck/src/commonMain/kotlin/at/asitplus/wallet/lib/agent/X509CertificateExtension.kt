package at.asitplus.wallet.lib.agent


import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import io.github.aakira.napier.Napier
import kotlin.time.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus

suspend fun X509Certificate.Companion.generateSelfSignedCertificate(
    publicKey: CryptoPublicKey,
    algorithm: X509SignatureAlgorithm,
    lifetimeInSeconds: Long = 30,
    extensions: List<X509CertificateExtension> = listOf(),
    signer: suspend (ByteArray) -> KmmResult<CryptoSignature>,
): KmmResult<X509Certificate> = catching {
    Napier.d { "Generating self-signed Certificate" }
    val notBeforeDate = Clock.System.now().truncateToSeconds()
    val notAfterDate = notBeforeDate.plus(lifetimeInSeconds, DateTimeUnit.SECOND)
    val tbsCertificate = TbsCertificate(
        version = 2,
        serialNumber = byteArrayOf(1),
        issuerName = listOf(
            RelativeDistinguishedName(
                AttributeTypeAndValue.CommonName(
                    Asn1String.UTF8("Default")
                )
            )
        ),
        validFrom = Asn1Time(notBeforeDate),
        validUntil = Asn1Time(notAfterDate),
        signatureAlgorithm = algorithm,
        subjectName = listOf(
            RelativeDistinguishedName(
                AttributeTypeAndValue.CommonName(
                    Asn1String.UTF8("Default")
                )
            )
        ),
        publicKey = publicKey,
        extensions = extensions
    )

    signer(tbsCertificate.encodeToDer()).map { signature ->
        X509Certificate(tbsCertificate, algorithm, signature)
    }.getOrThrow()

}