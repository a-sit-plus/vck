package at.asitplus.wallet.lib.agent

import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.toTransactionData
import io.ktor.util.*


internal fun List<TransactionDataBase64Url>?.hash(): Pair<String, List<ByteArray>>? {
    if (isNullOrEmpty()) return null
    val algorithm = parseAlgorithmPreferringSha256()
    val digest = algorithm.toDigest()
    val realAlgorithm = digest.toAlgorithmIdentifier(algorithm)
    return realAlgorithm to map { it.digest(digest) }
}

internal fun List<TransactionDataBase64Url>.parseAlgorithmPreferringSha256(): String =
    firstNotNullOf { base64url ->
        runCatching { base64url.toTransactionData() }.getOrNull()
            ?.transactionDataHashAlgorithms
            ?.let { algorithms ->
                algorithms.firstOrNull { it == SdJwtConstants.SHA_256 }
                    ?: algorithms.firstOrNull()
            }
            ?: SdJwtConstants.SHA_256
    }

// see https://www.iana.org/assignments/named-information/named-information.xhtml
internal fun String.toDigest(): Digest = when (toLowerCasePreservingASCIIRules()) {
    "sha-384" -> Digest.SHA384
    "sha-512" -> Digest.SHA512
    else -> Digest.SHA256
}

// see https://www.iana.org/assignments/named-information/named-information.xhtml
internal fun Digest.toAlgorithmIdentifier(algorithm: String): String = when (this) {
    Digest.SHA256 -> "sha-256"
    Digest.SHA384 -> "sha-384"
    Digest.SHA512 -> "sha-512"
    else -> throw PresentationException("Unsupported algorithm: $algorithm")
}