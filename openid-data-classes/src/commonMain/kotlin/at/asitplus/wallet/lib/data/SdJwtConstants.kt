package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.Digest

object SdJwtConstants {
    // IANA Naming convention https://www.iana.org/assignments/named-information/named-information.xhtml
    const val SHA_256 = "sha-256"
    const val SHA_384 = "sha-384"
    const val SHA_512 = "sha-512"
}

fun Digest.toIanaName(): String =
    when (this) {
        Digest.SHA256 -> SdJwtConstants.SHA_256
        Digest.SHA384 -> SdJwtConstants.SHA_384
        Digest.SHA512 -> SdJwtConstants.SHA_512
        Digest.SHA1 -> throw Exception("SHA1 not supported")
    }
