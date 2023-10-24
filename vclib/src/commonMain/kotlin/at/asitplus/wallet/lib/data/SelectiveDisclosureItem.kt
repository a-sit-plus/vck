package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.jws.SelectiveDisclosureItemSerializer
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

/**
 * Selective Disclosure item in SD-JWT format
 */
@Serializable(with = SelectiveDisclosureItemSerializer::class)
data class SelectiveDisclosureItem(
    val salt: ByteArray,
    val claimName: String,
    val claimValue: String,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SelectiveDisclosureItem

        if (!salt.contentEquals(other.salt)) return false
        if (claimName != other.claimName) return false
        if (claimValue != other.claimValue) return false

        return true
    }

    override fun hashCode(): Int {
        var result = salt.contentHashCode()
        result = 31 * result + claimName.hashCode()
        result = 31 * result + claimValue.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<SelectiveDisclosureItem>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}