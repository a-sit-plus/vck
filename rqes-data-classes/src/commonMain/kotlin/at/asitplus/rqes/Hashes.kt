package at.asitplus.rqes

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.Serializable

typealias Hashes = List<@Serializable(ByteArrayBase64Serializer::class) ByteArray>

fun Hashes.contentEquals(other: List<ByteArray>): Boolean {
    if (size != other.size) return false
    this.forEachIndexed {i, entry -> if (!entry.contentEquals(other[i])) return false }
    return true
}

fun Hashes.contentHashCode(): Int = this.sumOf {  31 * it.contentHashCode() }
