package at.asitplus.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.dcapi.NFCHandover
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.nullable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborArray
import kotlinx.serialization.cbor.CborTag.CBOR_ENCODED_DATA
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure
import kotlinx.serialization.encoding.encodeStructure
import kotlin.reflect.KClass

/**
 * Encodes a [SessionTranscript] as the CBOR array `[DeviceEngagementBytes / null, EReaderKeyBytes / null, Handover]`,
 * and decodes its handover as the kind its first two elements allow:
 * - With `DeviceEngagementBytes` and `EReaderKeyBytes` (ISO/IEC 18013-5:2021, 9.1.5.1): `null` for
 *   [SessionTranscript.Qr], or `[bstr, bstr / null]` for [SessionTranscript.Nfc], i.e. `NFCHandover`
 * - With both `null`: `[tstr, bstr]`, by its type [SessionTranscript.DcApi] (ISO/IEC 18013-7 Annex C, OpenID4VP 1.0
 *   B.2.6.2) or [SessionTranscript.OpenId4Vp] (OpenID4VP 1.0 B.2.6.1)
 *
 * A transcript decoded from its canonical encoding, as ISO/IEC 18013-5 requires, re-encodes to the same bytes.
 * Encoding does not depend on `encodeDefaults`. CBOR only.
 */
object SessionTranscriptSerializer : KSerializer<SessionTranscript> {

    // kotlinx-serialization CBOR has no way to peek at the next data item, and writes the value tags of an element
    // also before `null`. The descriptor has therefore separate elements for absent bytes, without a tag.
    @Serializable
    @CborArray
    @Suppress("unused")
    private class Layout(
        @ByteString
        @ValueTags(CBOR_ENCODED_DATA)
        val deviceEngagementBytes: ByteArray,
        @ByteString
        @ValueTags(CBOR_ENCODED_DATA)
        val eReaderKeyBytes: ByteArray,
        /** Either `null` or an array of two, with a primitive descriptor so that `null` is not encoded as a map. */
        val handover: String?,
        val absentDeviceEngagementBytes: String?,
        val absentEReaderKeyBytes: String?,
    )

    private const val DEVICE_ENGAGEMENT_BYTES = 0
    private const val E_READER_KEY_BYTES = 1
    private const val HANDOVER = 2
    private const val ABSENT_DEVICE_ENGAGEMENT_BYTES = 3
    private const val ABSENT_E_READER_KEY_BYTES = 4

    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.iso.SessionTranscript", Layout.serializer().descriptor)

    override fun serialize(encoder: Encoder, value: SessionTranscript) {
        encoder.encodeStructure(descriptor) {
            val proximity = value as? SessionTranscript.Proximity
            if (proximity != null) {
                encodeSerializableElement(
                    descriptor, DEVICE_ENGAGEMENT_BYTES, ByteArraySerializer(), proximity.deviceEngagementBytes
                )
                encodeSerializableElement(
                    descriptor, E_READER_KEY_BYTES, ByteArraySerializer(), proximity.eReaderKeyBytes
                )
            } else {
                encodeNullableSerializableElement(
                    descriptor, ABSENT_DEVICE_ENGAGEMENT_BYTES, String.serializer().nullable, null
                )
                encodeNullableSerializableElement(
                    descriptor, ABSENT_E_READER_KEY_BYTES, String.serializer().nullable, null
                )
            }
            when (value) {
                is SessionTranscript.Qr ->
                    encodeNullableSerializableElement(descriptor, HANDOVER, String.serializer().nullable, null)

                is SessionTranscript.Nfc ->
                    encodeSerializableElement(descriptor, HANDOVER, NFCHandover.serializer(), value.handover)

                is SessionTranscript.DcApi ->
                    encodeSerializableElement(descriptor, HANDOVER, DCAPIHandover.serializer(), value.handover)

                is SessionTranscript.OpenId4Vp ->
                    encodeSerializableElement(descriptor, HANDOVER, OpenId4VpHandover.serializer(), value.handover)
            }
        }
    }

    // The handover is decoded strictly as the kind that DeviceEngagementBytes and EReaderKeyBytes allow, never by trying
    // one kind and falling back to another: kotlinx-serialization CBOR may consume input, e.g. tags or the header of an
    // indefinite-length string, before it fails, so a fallback could accept malformed input.
    override fun deserialize(decoder: Decoder): SessionTranscript = decoder.decodeStructure(descriptor) {
        nextElement(DEVICE_ENGAGEMENT_BYTES)
        val deviceEngagementBytes =
            decodeNullableSerializableElement(descriptor, DEVICE_ENGAGEMENT_BYTES, ByteArraySerializer().nullable)
        nextElement(E_READER_KEY_BYTES)
        val eReaderKeyBytes =
            decodeNullableSerializableElement(descriptor, E_READER_KEY_BYTES, ByteArraySerializer().nullable)
        nextElement(HANDOVER)
        val transcript = when {
            deviceEngagementBytes != null && eReaderKeyBytes != null ->
                decodeNullableSerializableElement(descriptor, HANDOVER, NFCHandover.serializer().nullable)
                    ?.let { SessionTranscript.Nfc(deviceEngagementBytes, eReaderKeyBytes, it) }
                    ?: SessionTranscript.Qr(deviceEngagementBytes, eReaderKeyBytes)

            deviceEngagementBytes == null && eReaderKeyBytes == null ->
                decodeNullableSerializableElement(descriptor, HANDOVER, TypedHandover.serializer().nullable)
                    ?.toSessionTranscript()
                    ?: throw SerializationException("SessionTranscript without device engagement has no handover")

            else -> throw SerializationException(
                "SessionTranscript has to have both DeviceEngagementBytes and EReaderKeyBytes, or neither"
            )
        }
        if (decodeElementIndex(descriptor) != CompositeDecoder.DECODE_DONE)
            throw SerializationException("SessionTranscript has more than three elements")
        transcript
    }

    private fun CompositeDecoder.nextElement(expected: Int) {
        val index = decodeElementIndex(descriptor)
        if (index != expected)
            throw SerializationException("SessionTranscript has to be an array of three, missing element $expected")
    }

    /** A handover without device engagement, i.e. `[type, hash]`, identified by its type. */
    @Serializable
    @CborArray
    private class TypedHandover(
        val type: String,
        @ByteString
        val hash: ByteArray,
    ) {
        fun toSessionTranscript(): SessionTranscript = when (type) {
            DCAPIHandover.TYPE_DCAPI, DCAPIHandover.TYPE_OPENID4VP -> SessionTranscript.DcApi(DCAPIHandover(type, hash))
            OpenId4VpHandover.TYPE_OPENID4VP -> SessionTranscript.OpenId4Vp(OpenId4VpHandover(type, hash))
            else -> throw SerializationException("Unsupported handover type $type")
        }
    }

    /** Serializes one subtype of [SessionTranscript], for its static type, e.g. `encodeToByteArray(transcript)`. */
    sealed class Subtype<T : SessionTranscript>(private val type: KClass<T>) : KSerializer<T> {
        override val descriptor: SerialDescriptor get() = SessionTranscriptSerializer.descriptor

        override fun serialize(encoder: Encoder, value: T) = SessionTranscriptSerializer.serialize(encoder, value)

        @Suppress("UNCHECKED_CAST")
        override fun deserialize(decoder: Decoder): T = SessionTranscriptSerializer.deserialize(decoder).let {
            if (type.isInstance(it)) it as T
            else throw SerializationException("Expected a ${type.simpleName} SessionTranscript, got $it")
        }
    }

    object Qr : Subtype<SessionTranscript.Qr>(SessionTranscript.Qr::class)
    object Nfc : Subtype<SessionTranscript.Nfc>(SessionTranscript.Nfc::class)
    object DcApi : Subtype<SessionTranscript.DcApi>(SessionTranscript.DcApi::class)
    object OpenId4Vp : Subtype<SessionTranscript.OpenId4Vp>(SessionTranscript.OpenId4Vp::class)
}
