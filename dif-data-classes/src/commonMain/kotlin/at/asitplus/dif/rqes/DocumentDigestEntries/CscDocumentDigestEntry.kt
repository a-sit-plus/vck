package at.asitplus.dif.rqes.DocumentDigestEntries

import at.asitplus.signum.indispensable.asn1.ObjectIdentifier

data class CscDocumentDigestEntry(
    //TODO CSC Page 78
    val hashes: List<ByteArray>,
    val hashAlgorithmOid: ObjectIdentifier,
    val signatureFormat: String,
    val conformanceLevel: String,
    val signAlgo: String,
    val signAlgoParams: String,
    val signedProps: List<String>,
    val signedEnvelopeProperty: String,
)