package at.asitplus.wallet.lib.agent


import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.asn1.Asn1EncapsulatingOctetString
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.Asn1Time
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.asn1Sequence
import at.asitplus.crypto.datatypes.pki.AttributeTypeAndValue
import at.asitplus.crypto.datatypes.pki.RelativeDistinguishedName
import at.asitplus.crypto.datatypes.pki.SubjectAltNameImplicitTags
import at.asitplus.crypto.datatypes.pki.TbsCertificate
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.datatypes.pki.X509CertificateExtension
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlin.random.Random

fun X509Certificate.Companion.generateSelfSignedCertificate(
    cryptoService: CryptoService,
    commonName: String = "DefaultCryptoService"
): X509Certificate {
    val notBeforeDate = Clock.System.now()
    val notAfterDate = notBeforeDate.plus(30, DateTimeUnit.SECOND)
    val extension = X509CertificateExtension(
        KnownOIDs.subjectAltName_2_5_29_17,
        critical = false,
        Asn1EncapsulatingOctetString(listOf(
            asn1Sequence {
                append(
                    Asn1Primitive(
                        SubjectAltNameImplicitTags.dNSName,
                        Asn1String.UTF8("example.com").encodeToTlv().content
                    )
                )
            }
        )))
    val tbsCertificate = TbsCertificate(
        version = 2,
        serialNumber = Random.nextBytes(8),
        issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
        validFrom = Asn1Time(notBeforeDate),
        validUntil = Asn1Time(notAfterDate),
        signatureAlgorithm = cryptoService.algorithm,
        subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
        publicKey = cryptoService.publicKey,
        extensions = listOf(extension)
    )
    val signature = runBlocking {
        runCatching { tbsCertificate.encodeToDer() }
            .wrap()
            .transform { cryptoService.sign(it) }
            .getOrThrow()
    }
    return X509Certificate(tbsCertificate, cryptoService.algorithm, signature)
}