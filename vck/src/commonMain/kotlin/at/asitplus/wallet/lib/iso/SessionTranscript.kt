package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Session transcript and cipher suite (9.1.5.1) and
 * ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 */
@Serializable
@CborArray
data class SessionTranscript(
    /** Set to `null` for OID4VP with ISO/IEC 18013-7 */
    @ByteString
    val deviceEngagementBytes: ByteArray?,
    /** Set to `null` for OID4VP with ISO/IEC 18013-7 */
    @ByteString
    val eReaderKeyBytes: ByteArray?,
    @ValueTags(24U)
    val handover: ByteStringWrapper<OID4VPHandover>,
) {

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SessionTranscript

        if (!deviceEngagementBytes.contentEquals(other.deviceEngagementBytes)) return false
        if (!eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)) return false
        if (handover != other.handover) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceEngagementBytes?.contentHashCode() ?: 0
        result = 31 * result + (eReaderKeyBytes?.contentHashCode() ?: 0)
        result = 31 * result + handover.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<SessionTranscript>(it)
        }.wrap()
    }
}