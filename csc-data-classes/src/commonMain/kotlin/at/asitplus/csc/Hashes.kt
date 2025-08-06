package at.asitplus.csc

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

typealias Hashes = List<@Serializable(ByteArrayBase64Serializer::class) ByteArray>

fun Hashes?.contentEquals(other: Hashes?): Boolean = when (this) {
    null -> other == null
    else -> other?.let {
        if (size != other.size) return false
        this.forEachIndexed { i, entry -> if (!entry.contentEquals(other[i])) return false }
        true
    } ?: false
}

fun Hashes.contentHashCode(): Int = this.sumOf { 31 * it.contentHashCode() }
