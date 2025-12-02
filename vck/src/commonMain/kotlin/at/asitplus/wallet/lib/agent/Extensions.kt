package at.asitplus.wallet.lib.agent

import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.util.*

internal fun List<TransactionDataBase64Url>.hash(digest: Digest?): List<ByteArray> =
    map { transactionData -> transactionData.digest(digest ?: Digest.SHA256) }

internal fun getCommonHashesAlgorithms(transactionData: List<TransactionDataBase64Url>?): Set<String>? {
    val listOfSets = transactionData?.map {
        vckJsonSerializer.decodeFromJsonElement(Base64URLTransactionDataSerializer, it).transactionDataHashAlgorithms
    }
    return if (listOfSets == null || listOfSets.any { it == null }) {
        null
    } else {
        listOfSets.filterNotNull()
            .reduceOrNull { acc, set -> acc intersect set }
            ?.takeIf { it.isNotEmpty() }
    }
}

fun Digest.toIanaName(): String =
    when (this) {
        Digest.SHA256 -> SdJwtConstants.SHA_256
        Digest.SHA384 -> SdJwtConstants.SHA_384
        Digest.SHA512 -> SdJwtConstants.SHA_512
        Digest.SHA1 -> throw Exception("SHA1 not supported")
    }

// see https://www.iana.org/assignments/named-information/named-information.xhtml
internal fun String?.toDigest(): Digest? =
    when (this?.toLowerCasePreservingASCIIRules()) {
        SdJwtConstants.SHA_256 -> Digest.SHA256
        SdJwtConstants.SHA_384 -> Digest.SHA384
        SdJwtConstants.SHA_512 -> Digest.SHA512
        null -> null
        else -> throw Exception("Unsupported digest name $this")
    }
