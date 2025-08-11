package at.asitplus.rqes

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import io.github.aakira.napier.Napier

internal fun ObjectIdentifier.getSignAlgorithm(signAlgoParams: Asn1Element?): SignatureAlgorithm? =
    catchingUnwrapped {
        X509SignatureAlgorithm.entries.first {
            it.oid == this && it.parameters == (signAlgoParams?.let { listOf(it) }
                ?: if (it is X509SignatureAlgorithm.RSAPKCS1) listOf(Asn1Null) //bend towards X.509 sig alg
                else emptyList<Asn1Element>())
        }.algorithm.also {
            require(
                when (it) {
                    is SignatureAlgorithm.ECDSA -> it.digest
                    is SignatureAlgorithm.RSA -> it.digest
                } != Digest.SHA1
            )
        }
    }.getOrElse {
        Napier.w { "Could not resolve $this" }
        null
    }

@Throws(Exception::class)
internal fun ObjectIdentifier?.getHashAlgorithm(signatureAlgorithm: SignatureAlgorithm? = null) =
    this?.let {
        Digest.entries.find { digest -> digest.oid == it }
    } ?: when (signatureAlgorithm) {
        is SignatureAlgorithm.ECDSA -> signatureAlgorithm.digest
        is SignatureAlgorithm.RSA -> signatureAlgorithm.digest
        null -> null
    } ?: throw Exception("Unknown hashing algorithm defined with oid $this or signature algorithm $signatureAlgorithm")
