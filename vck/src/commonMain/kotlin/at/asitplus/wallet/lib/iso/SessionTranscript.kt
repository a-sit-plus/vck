package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborTag.CBOR_ENCODED_DATA
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
    @ValueTags(CBOR_ENCODED_DATA)
    val deviceEngagementBytes: ByteArray?,
    /** Set to `null` for OID4VP with ISO/IEC 18013-7 */
    @ByteString
    @ValueTags(CBOR_ENCODED_DATA)
    val eReaderKeyBytes: ByteArray?,
    val oid4VPHandover: OID4VPHandover? = null,
    val nfcHandover: NFCHandover? = null
) {
    init {
        check(oid4VPHandover != null || nfcHandover != null) { "One handover element must be set" }
        check(!(oid4VPHandover == null && nfcHandover == null)) { "Only one handover element must be set" }
    }

    fun serialize() = vckCborSerializer.encodeToByteArray(this)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SessionTranscript

        if (deviceEngagementBytes != null) {
            if (other.deviceEngagementBytes == null) return false
            if (!deviceEngagementBytes.contentEquals(other.deviceEngagementBytes)) return false
        } else if (other.deviceEngagementBytes != null) return false
        if (eReaderKeyBytes != null) {
            if (other.eReaderKeyBytes == null) return false
            if (!eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)) return false
        } else if (other.eReaderKeyBytes != null) return false
        if (oid4VPHandover != other.oid4VPHandover) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceEngagementBytes?.contentHashCode() ?: 0
        result = 31 * result + (eReaderKeyBytes?.contentHashCode() ?: 0)
        result = 31 * result + oid4VPHandover.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: ByteArray) = runCatching {
            vckCborSerializer.decodeFromByteArray<SessionTranscript>(it)
        }.wrap()
    }
}