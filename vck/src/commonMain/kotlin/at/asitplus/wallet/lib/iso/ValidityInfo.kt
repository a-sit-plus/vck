package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Data structure for MSO (9.1.2.4)
 */
@Serializable
data class ValidityInfo(
    @SerialName("signed")
    val signed: Instant,
    @SerialName("validFrom")
    val validFrom: Instant,
    @SerialName("validUntil")
    val validUntil: Instant,
    @SerialName("expectedUpdate")
    val expectedUpdate: Instant? = null,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) = kotlin.runCatching {
            vckCborSerializer.decodeFromByteArray<ValidityInfo>(it)
        }.wrap()
    }
}