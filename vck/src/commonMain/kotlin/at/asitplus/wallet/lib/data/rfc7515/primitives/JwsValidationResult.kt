package at.asitplus.wallet.lib.data.rfc7515.primitives

import kotlinx.serialization.json.JsonObject

data class JwsValidationResult(
    val commonHeaders: JsonObject,
    val payload: ByteArray,
    val signatureValidities: List<Boolean>,
) {
    val isValid: Boolean?
        get() = if (signatureValidities.all { it }) true
        else if (!signatureValidities.any { it }) false
        else null

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsValidationResult

        if (!payload.contentEquals(other.payload)) return false
        if (signatureValidities != other.signatureValidities) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.contentHashCode()
        result = 31 * result + signatureValidities.hashCode()
        return result
    }
}