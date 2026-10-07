package at.asitplus.csc

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import io.github.aakira.napier.Napier


internal fun ObjectIdentifier.getSignAlgorithm(signAlgoParams: Asn1Element?): SignatureAlgorithm? =
    catchingUnwrapped {
        (EcdsaAlgorithm.entries + RsaAlgorithm.entries).first {
            val identifier = it.asn1Representation
            identifier.oid == this && identifier.parameters == (signAlgoParams
                ?: if (it is RsaAlgorithm && it.parameters is RsaAlgorithm.Parameters.Pkcs1Padded)
                    Asn1Null // bend towards X.509 signature algorithms
                else null)
        }.also {
            require(
                when (it) {
                    is EcdsaAlgorithm -> it.digest
                    is RsaAlgorithm -> it.digest
                    else -> null
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
        WellKnownDigest.entries.find { digest -> digest.oid == it }
    } ?: when (signatureAlgorithm) {
        is EcdsaAlgorithm -> signatureAlgorithm.digest
        is RsaAlgorithm -> signatureAlgorithm.digest
        else -> null
    } ?: throw Exception("Unknown hashing algorithm defined with oid $this or signature algorithm $signatureAlgorithm")
