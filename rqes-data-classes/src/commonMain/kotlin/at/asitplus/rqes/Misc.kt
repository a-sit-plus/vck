package at.asitplus.rqes

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import io.github.aakira.napier.Napier


internal fun getSignAlgorithm(signAlgoOid: ObjectIdentifier, signAlgoParams: Asn1Element?): SignatureAlgorithm? =
    runCatching {
        X509SignatureAlgorithm.doDecode(Asn1.Sequence {
            +signAlgoOid
            +(signAlgoParams ?: Asn1.Null())
        }).also {
            require(it.digest != Digest.SHA1)
        }.algorithm
    }.getOrElse {
        Napier.w { "Could not resolve $signAlgoOid" }
        null
    }

@Throws(Exception::class)
internal fun getHashAlgorithm(hashAlgorithmOid: ObjectIdentifier?, signatureAlgorithm: SignatureAlgorithm? = null) =
    hashAlgorithmOid?.let {
        Digest.entries.find { digest -> digest.oid == it }
    } ?: when(signatureAlgorithm) {
        is SignatureAlgorithm.ECDSA -> signatureAlgorithm.digest
        is SignatureAlgorithm.HMAC -> signatureAlgorithm.digest
        is SignatureAlgorithm.RSA -> signatureAlgorithm.digest
        null -> null
    } ?: throw Exception("Unknown hashing algorithm defined with oid $hashAlgorithmOid or signature algorithm $signatureAlgorithm")
