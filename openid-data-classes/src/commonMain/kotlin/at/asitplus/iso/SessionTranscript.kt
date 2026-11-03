package at.asitplus.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.NFCHandover
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable

/**
 * Part of the ISO/IEC 18013-5:2021 standard: Session transcript and cipher suite (9.1.5.1),
 * ISO/IEC 18013-7:2024 standard: Session Transcript (B.4.4), and OpenID for Verifiable Presentations 1.0 (B.2.6):
 *
 * ```
 * SessionTranscript = [
 *   DeviceEngagementBytes / null,
 *   EReaderKeyBytes / null,
 *   Handover
 * ]
 * ```
 *
 * One subtype per kind of handover, see [SessionTranscriptSerializer] for the encoding.
 */
@Serializable(with = SessionTranscriptSerializer::class)
sealed interface SessionTranscript {

    /** The transcript of an ISO/IEC 18013-5 proximity session, which starts with device engagement. */
    sealed interface Proximity : SessionTranscript {
        /** The encoded `DeviceEngagement`, i.e. the content of `DeviceEngagementBytes`. */
        val deviceEngagementBytes: ByteArray

        /** The encoded `EReaderKey` (a `COSE_Key`), i.e. the content of `EReaderKeyBytes`. */
        val eReaderKeyBytes: ByteArray
    }

    /** After device engagement with a QR code, i.e. `QRHandover` is `null` (ISO/IEC 18013-5:2021, 9.1.5.1). */
    @Serializable(with = SessionTranscriptSerializer.Qr::class)
    class Qr(
        override val deviceEngagementBytes: ByteArray,
        override val eReaderKeyBytes: ByteArray,
    ) : Proximity {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Qr) return false
            return deviceEngagementBytes.contentEquals(other.deviceEngagementBytes) &&
                    eReaderKeyBytes.contentEquals(other.eReaderKeyBytes)
        }

        override fun hashCode(): Int =
            31 * deviceEngagementBytes.contentHashCode() + eReaderKeyBytes.contentHashCode()

        override fun toString(): String = "SessionTranscript.Qr(" +
                "deviceEngagementBytes=${deviceEngagementBytes.encodeToString(Base16Strict)}, " +
                "eReaderKeyBytes=${eReaderKeyBytes.encodeToString(Base16Strict)})"
    }

    /** After device engagement with NFC, with the [handover] messages (ISO/IEC 18013-5:2021, 9.1.5.1). */
    @Serializable(with = SessionTranscriptSerializer.Nfc::class)
    class Nfc(
        override val deviceEngagementBytes: ByteArray,
        override val eReaderKeyBytes: ByteArray,
        val handover: NFCHandover,
    ) : Proximity {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Nfc) return false
            return deviceEngagementBytes.contentEquals(other.deviceEngagementBytes) &&
                    eReaderKeyBytes.contentEquals(other.eReaderKeyBytes) &&
                    handover == other.handover
        }

        override fun hashCode(): Int {
            var result = deviceEngagementBytes.contentHashCode()
            result = 31 * result + eReaderKeyBytes.contentHashCode()
            result = 31 * result + handover.hashCode()
            return result
        }

        override fun toString(): String = "SessionTranscript.Nfc(" +
                "deviceEngagementBytes=${deviceEngagementBytes.encodeToString(Base16Strict)}, " +
                "eReaderKeyBytes=${eReaderKeyBytes.encodeToString(Base16Strict)}, " +
                "handover=$handover)"
    }

    /**
     * Over the Digital Credentials API, acc. to ISO/IEC 18013-7 Annex C or OpenID for Verifiable Presentations 1.0
     * (B.2.6.2), without device engagement.
     */
    @Serializable(with = SessionTranscriptSerializer.DcApi::class)
    data class DcApi(
        val handover: DCAPIHandover,
    ) : SessionTranscript

    /** Over OpenID for Verifiable Presentations 1.0 without the Digital Credentials API (B.2.6.1). */
    @Serializable(with = SessionTranscriptSerializer.OpenId4Vp::class)
    data class OpenId4Vp(
        val handover: OpenId4VpHandover,
    ) : SessionTranscript

    companion object {
        @Deprecated(
            "Use the constructor of the subtype",
            ReplaceWith("SessionTranscript.Nfc(deviceEngagementBytes, eReaderKeyBytes, nfcHandover)")
        )
        fun forNfc(
            deviceEngagementBytes: ByteArray,
            eReaderKeyBytes: ByteArray,
            nfcHandover: NFCHandover,
        ): SessionTranscript = Nfc(deviceEngagementBytes, eReaderKeyBytes, nfcHandover)

        @Deprecated("Use the constructor of the subtype", ReplaceWith("SessionTranscript.OpenId4Vp(handover)"))
        fun forOpenId(
            handover: OpenId4VpHandover,
        ): SessionTranscript = OpenId4Vp(handover)

        @Deprecated("Use the constructor of the subtype", ReplaceWith("SessionTranscript.DcApi(handover)"))
        fun forDcApi(
            handover: DCAPIHandover,
        ): SessionTranscript = DcApi(handover)

        @Deprecated(
            "Use the constructor of the subtype",
            ReplaceWith("SessionTranscript.Qr(deviceEngagementBytes, eReaderKeyBytes)")
        )
        fun forQr(
            deviceEngagementBytes: ByteArray,
            eReaderKeyBytes: ByteArray,
        ): SessionTranscript = Qr(deviceEngagementBytes, eReaderKeyBytes)
    }
}
