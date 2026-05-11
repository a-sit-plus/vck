package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

@Serializable(with = OpenId4VciClaimsPathPointerSegment.Serializer::class)
sealed interface OpenId4VciClaimsPathPointerSegment {
    class Serializer : KSerializer<OpenId4VciClaimsPathPointerSegment> {
        private val delegate = JsonPrimitive.Companion.serializer()
        override val descriptor: SerialDescriptor
            get() = SerialDescriptor(
                original = delegate.descriptor,
                serialName = Serializer::class.qualifiedName!!
            )

        override fun serialize(
            encoder: Encoder,
            value: OpenId4VciClaimsPathPointerSegment
        ) {
            encoder.encodeSerializableValue(
                delegate,
                when (value) {
                    is OpenId4VciClaimsPathPointerSegmentIndex -> JsonPrimitive(value.uint)
                    is OpenId4VciClaimsPathPointerSegmentString -> JsonPrimitive(value.string)
                }
            )
        }

        override fun deserialize(decoder: Decoder): OpenId4VciClaimsPathPointerSegment {
            val jsonPrimitive = decoder.decodeSerializableValue(delegate)
            return when {
                jsonPrimitive.isString -> OpenId4VciClaimsPathPointerSegmentString(jsonPrimitive.content)
                else -> jsonPrimitive.longOrNull?.let {
                    if (it < 0 || it.toULong() > UInt.MAX_VALUE) {
                        throw UnsupportedOperationException("Expected index segment to be in range 0..${UInt.MAX_VALUE}, but was $it")
                    }
                    OpenId4VciClaimsPathPointerSegmentIndex(it.toUInt())
                } ?: throw IllegalArgumentException(
                    "Expected value to be either a string or a number, but was: $jsonPrimitive"
                )
            }
        }
    }
}