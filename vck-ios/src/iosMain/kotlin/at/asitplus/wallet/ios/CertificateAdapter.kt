@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.ios

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import platform.Foundation.NSData
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateRef

object CertificateAdapter {
    fun fromSecCertificate(certificate: SecCertificateRef?): KmmResult<X509Certificate> = catching {
        X509Certificate.decodeFromByteArray(
            SecCertificateCopyData(requireNotNull(certificate) { "certificate must not be null" })
                .takeFromCF<NSData>()
                .toByteArray(),
        ) ?: throw IllegalArgumentException("Invalid X.509 certificate")
    }
}
