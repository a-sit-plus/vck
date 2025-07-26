package at.asitplus.wallet.lib.data

import kotlin.time.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SealedSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ValueTags
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.SerialKind
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Might be used for `expiry_date` or `issue_date` in EU PIDs, where issuers may put in a "tdate" or "full-date"
 */
@Serializable(with = LocalDateOrInstantSerializer::class)
sealed class LocalDateOrInstant {
    data class LocalDate(val value: kotlinx.datetime.LocalDate) : LocalDateOrInstant()
    data class Instant(val value: kotlin.time.Instant) : LocalDateOrInstant()
}

object LocalDateOrInstantSerializer : KSerializer<LocalDateOrInstant> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("LocalDateOrInstant", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): LocalDateOrInstant = with(decoder.decodeString()) {
        if (length > 10) // "1990-01-01"
            LocalDateOrInstant.Instant(Instant.Companion.parse(this))
        else
            LocalDateOrInstant.LocalDate(LocalDate.Companion.parse(this))
    }

    override fun serialize(encoder: Encoder, value: LocalDateOrInstant) {
        when (value) {
            is LocalDateOrInstant.Instant -> encoder
                .encodeInline(InstantDescriptor)
                .encodeString(value.value.toString())

            is LocalDateOrInstant.LocalDate -> encoder
                .encodeInline(LocalDateDescriptor)
                .encodeString(value.value.toString())
        }
    }

}

/**
 * Sets the correct CBOR tag (0u) when serializing instants from [LocalDateOrInstant.Instant]
 */
@OptIn(SealedSerializationApi::class)
object InstantDescriptor : SerialDescriptor {
    @ExperimentalSerializationApi
    override val elementsCount: Int = 1

    @ExperimentalSerializationApi
    override val kind: SerialKind = PrimitiveKind.STRING

    @ExperimentalSerializationApi
    override val serialName: String = "LocalDateOrInstant.Instant"

    @ExperimentalSerializationApi
    @OptIn(ExperimentalUnsignedTypes::class)
    override fun getElementAnnotations(index: Int): List<Annotation> = listOf(ValueTags(0U))

    @ExperimentalSerializationApi
    override fun getElementDescriptor(index: Int): SerialDescriptor = throw IllegalStateException()

    @ExperimentalSerializationApi
    override fun getElementIndex(name: String): Int = CompositeDecoder.Companion.UNKNOWN_NAME

    @ExperimentalSerializationApi
    override fun getElementName(index: Int): String = throw IllegalStateException()

    @ExperimentalSerializationApi
    override fun isElementOptional(index: Int): Boolean = throw IllegalStateException()
}

/**
 * Sets the correct CBOR tag (1004u) when serializing local dates from [LocalDateOrInstant.LocalDate]
 */
@OptIn(SealedSerializationApi::class)
object LocalDateDescriptor : SerialDescriptor {
    @ExperimentalSerializationApi
    override val elementsCount: Int = 1

    @ExperimentalSerializationApi
    override val kind: SerialKind = PrimitiveKind.STRING

    @ExperimentalSerializationApi
    override val serialName: String = "LocalDateOrInstant.LocalDate"

    @ExperimentalSerializationApi
    @OptIn(ExperimentalUnsignedTypes::class)
    override fun getElementAnnotations(index: Int): List<Annotation> = listOf(ValueTags(1004U))

    @ExperimentalSerializationApi
    override fun getElementDescriptor(index: Int): SerialDescriptor = throw IllegalStateException()

    @ExperimentalSerializationApi
    override fun getElementIndex(name: String): Int = CompositeDecoder.Companion.UNKNOWN_NAME

    @ExperimentalSerializationApi
    override fun getElementName(index: Int): String = throw IllegalStateException()

    @ExperimentalSerializationApi
    override fun isElementOptional(index: Int): Boolean = throw IllegalStateException()
}