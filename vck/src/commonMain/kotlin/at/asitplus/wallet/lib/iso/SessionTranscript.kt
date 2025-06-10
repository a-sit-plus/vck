package at.asitplus.wallet.lib.iso

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborTag.CBOR_ENCODED_DATA
import kotlinx.serialization.cbor.ValueTags

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Session transcript and cipher suite (9.1.5.1) and
 * ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4)
 * Must be used with encodeDefaults = false
 */
@Serializable
@CborArray
@ConsistentCopyVisibility
data class SessionTranscript private constructor(
    @ByteString
    @ValueTags(CBOR_ENCODED_DATA)
    val deviceEngagementBytes: ByteArray? = null,
    @ByteString
    @ValueTags(CBOR_ENCODED_DATA)
    val eReaderKeyBytes: ByteArray? = null,
    // Can be removed once https://github.com/Kotlin/kotlinx.serialization/issues/2966 is fixed
    // Cannot be a ByteArray because encodeDefaults = false does not work with non-null values for ByteArrays
    /** Set to `null` for OID4VP with ISO/IEC 18013-7 or for QR Handover */
    val deviceEngagementBytesOid: Int? = 42,
    /** Set to `null` for OID4VP with ISO/IEC 18013-7 */
    val eReaderKeyBytesOid: Int? = 42,
    /** Set either this or [nfcHandover] or deviceEngagementBytesOid to null for QR engagement */
    val oid4VPHandover: OID4VPHandover? = null,
    /** Set either this or [oid4VPHandover] or deviceEngagementBytesOid to null for QR engagement */
    val nfcHandover: NFCHandover? = null,
    val dcapiHandover: DCAPIHandover? = null,
) {
    init {
        val nrOfHandovers = listOf(oid4VPHandover, nfcHandover, dcapiHandover).count { it != null }
        check(nrOfHandovers == 1 || (deviceEngagementBytesOid == null && nrOfHandovers == 0)) { "Exactly one handover element must be set (or null for QR Handover)" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SessionTranscript

        if (deviceEngagementBytesOid != other.deviceEngagementBytesOid) return false
        if (eReaderKeyBytesOid != other.eReaderKeyBytesOid) return false
        if (!deviceEngagementBytes.contentEquals(other.deviceEngagementBytes)) return false
        if (!eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)) return false
        if (oid4VPHandover != other.oid4VPHandover) return false
        if (nfcHandover != other.nfcHandover) return false
        if (dcapiHandover != other.dcapiHandover) return false

        return true
    }

    override fun hashCode(): Int {
        var result = deviceEngagementBytesOid ?: 0
        result = 31 * result + (eReaderKeyBytesOid ?: 0)
        result = 31 * result + (deviceEngagementBytes?.contentHashCode() ?: 0)
        result = 31 * result + (eReaderKeyBytes?.contentHashCode() ?: 0)
        result = 31 * result + (oid4VPHandover?.hashCode() ?: 0)
        result = 31 * result + (nfcHandover?.hashCode() ?: 0)
        result = 31 * result + (dcapiHandover?.hashCode() ?: 0)
        return result
    }

    companion object {

        fun forNfc(
            deviceEngagementBytes: ByteArray,
            eReaderKeyBytes: ByteArray,
            nfcHandover: NFCHandover,
        ): SessionTranscript = SessionTranscript(
            deviceEngagementBytes = deviceEngagementBytes,
            eReaderKeyBytes = eReaderKeyBytes,
            nfcHandover = nfcHandover
        )

        fun forOpenId(
            handover: OID4VPHandover,
        ): SessionTranscript = SessionTranscript(
            deviceEngagementBytesOid = null,
            eReaderKeyBytesOid = null,
            oid4VPHandover = handover,
        )

        fun forDcApi(
            handover: DCAPIHandover,
        ): SessionTranscript = SessionTranscript(
            deviceEngagementBytesOid = null,
            eReaderKeyBytesOid = null,
            dcapiHandover = handover,
        )

        fun forQr(
            deviceEngagementBytes: ByteArray,
            eReaderKeyBytes: ByteArray,
        ): SessionTranscript = SessionTranscript(
            deviceEngagementBytes = deviceEngagementBytes,
            eReaderKeyBytes = eReaderKeyBytes,
            deviceEngagementBytesOid = null
        )
    }
}