package at.asitplus.iso

import at.asitplus.catchingUnwrapped
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
 * and decodes it by the shape of its handover:
 * - `null`: [SessionTranscript.Qr] (ISO/IEC 18013-5:2021, 9.1.5.1)
 * - `[bstr, bstr / null]`: [SessionTranscript.Nfc], i.e. `NFCHandover` (ISO/IEC 18013-5:2021, 9.1.5.1)
 * - `[tstr, bstr]`: by its type, [SessionTranscript.DcApi] (ISO/IEC 18013-7 Annex C, OpenID4VP 1.0 B.2.6.2) or
 *   [SessionTranscript.OpenId4Vp] (OpenID4VP 1.0 B.2.6.1)
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

    @Serializable
    @CborArray
    @Suppress("unused")
    private class HandoverLayout(
        @ByteString
        val first: ByteArray,
        @ByteString
        val second: ByteArray?,
    )

    private const val DEVICE_ENGAGEMENT_BYTES = 0
    private const val E_READER_KEY_BYTES = 1
    private const val HANDOVER = 2
    private const val ABSENT_DEVICE_ENGAGEMENT_BYTES = 3
    private const val ABSENT_E_READER_KEY_BYTES = 4

    @OptIn(ExperimentalSerializationApi::class)
    override val descriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.iso.SessionTranscript", Layout.serializer().descriptor)

    @OptIn(ExperimentalSerializationApi::class)
    private val handoverDescriptor: SerialDescriptor =
        SerialDescriptor("at.asitplus.iso.SessionTranscript.Handover", HandoverLayout.serializer().descriptor)

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

    override fun deserialize(decoder: Decoder): SessionTranscript = decoder.decodeStructure(descriptor) {
        nextElement(DEVICE_ENGAGEMENT_BYTES)
        val deviceEngagementBytes =
            decodeNullableSerializableElement(descriptor, DEVICE_ENGAGEMENT_BYTES, ByteArraySerializer().nullable)
        nextElement(E_READER_KEY_BYTES)
        val eReaderKeyBytes =
            decodeNullableSerializableElement(descriptor, E_READER_KEY_BYTES, ByteArraySerializer().nullable)
        nextElement(HANDOVER)
        val handover = decodeNullableSerializableElement(descriptor, HANDOVER, HandoverDeserializer.nullable)
        if (decodeElementIndex(descriptor) != CompositeDecoder.DECODE_DONE)
            throw SerializationException("SessionTranscript has more than three elements")
        when {
            handover == null -> SessionTranscript.Qr(
                deviceEngagementBytes ?: throw SerializationException("QR handover without DeviceEngagementBytes"),
                eReaderKeyBytes ?: throw SerializationException("QR handover without EReaderKeyBytes"),
            )

            handover is NFCHandover -> SessionTranscript.Nfc(
                deviceEngagementBytes ?: throw SerializationException("NFC handover without DeviceEngagementBytes"),
                eReaderKeyBytes ?: throw SerializationException("NFC handover without EReaderKeyBytes"),
                handover,
            )

            deviceEngagementBytes != null || eReaderKeyBytes != null ->
                throw SerializationException("Handover $handover does not have device engagement")

            handover is DCAPIHandover -> SessionTranscript.DcApi(handover)
            handover is OpenId4VpHandover -> SessionTranscript.OpenId4Vp(handover)
            else -> throw SerializationException("Unsupported handover $handover")
        }
    }

    private fun CompositeDecoder.nextElement(expected: Int) {
        val index = decodeElementIndex(descriptor)
        if (index != expected)
            throw SerializationException("SessionTranscript has to be an array of three, missing element $expected")
    }

    /** Decodes a non-null handover, i.e. an array of two, by the major type of its first element. */
    private object HandoverDeserializer : KSerializer<Any> {
        override val descriptor: SerialDescriptor get() = handoverDescriptor

        override fun serialize(encoder: Encoder, value: Any) =
            throw UnsupportedOperationException("Only for decoding")

        override fun deserialize(decoder: Decoder): Any = decoder.decodeStructure(descriptor) {
            if (decodeElementIndex(descriptor) != 0) throw SerializationException("Handover is empty")
            // Decoding a text string fails before it consumes another data item, e.g. a byte string
            val type = catchingUnwrapped { decodeStringElement(descriptor, 0) }.getOrNull()
            val first = if (type == null) decodeSerializableElement(descriptor, 0, ByteArraySerializer()) else null
            if (decodeElementIndex(descriptor) != 1) throw SerializationException("Handover has one element")
            val handover = when (type) {
                null -> NFCHandover(
                    handoverSelect = first!!,
                    handoverRequest = decodeNullableSerializableElement(descriptor, 1, ByteArraySerializer().nullable),
                )

                DCAPIHandover.TYPE_DCAPI, DCAPIHandover.TYPE_OPENID4VP ->
                    DCAPIHandover(type, decodeSerializableElement(descriptor, 1, ByteArraySerializer()))

                OpenId4VpHandover.TYPE_OPENID4VP ->
                    OpenId4VpHandover(type, decodeSerializableElement(descriptor, 1, ByteArraySerializer()))

                else -> throw SerializationException("Unsupported handover type $type")
            }
            if (decodeElementIndex(descriptor) != CompositeDecoder.DECODE_DONE)
                throw SerializationException("Handover has more than two elements")
            handover
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
