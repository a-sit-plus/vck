package at.asitplus.wallet.sdjwt

import at.asitplus.jsonpath.core.NormalizedJsonPath
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.jvm.JvmInline

@JvmInline
@Serializable
value class SdJwtTypeMetadataClaimInformationPath(
    private val segments: List<@Serializable(with = SegmentSerializer::class) SdJwtTypeMetadataClaimInformationPathSegment?>
) : List<SdJwtTypeMetadataClaimInformationPathSegment?> by segments {
    init {
        require(segments.isNotEmpty()) {
            "Expected at least 1 segment, but there were 0."
        }
    }

    fun process(jsonElement: JsonElement) = segments.fold(
        listOf(
            NormalizedJsonPath() to jsonElement
        )
    ) { currentList, segment ->
        when (segment) {
            is SdJwtTypeMetadataClaimInformationPathSegmentName -> currentList.mapNotNull { (path, element) ->
                element.jsonObject[segment.string]?.let {
                    (path + segment.string) to it
                }
            }

            is SdJwtTypeMetadataClaimInformationPathSegmentIndex -> currentList.mapNotNull { (path, element) ->
                if (segment.ulong > Int.MAX_VALUE.toULong()) null
                else element.jsonArray.getOrNull(segment.ulong.toInt())?.let {
                    (path + segment.ulong.toUInt()) to it
                }
            }

            null -> currentList.flatMap { (path, element) ->
                element.jsonArray.mapIndexed { index, element ->
                    (path + index.toUInt()) to element
                }
            }
        }
    }.also {
        require(it.isNotEmpty()) {
            "Expected at least one element to match the given path, but there were none."
        }
    }

    constructor(
        startSegment: SdJwtTypeMetadataClaimInformationPathSegment,
        vararg segments: SdJwtTypeMetadataClaimInformationPathSegment,
    ) : this(listOf(startSegment, *segments))

    @ExperimentalUnsignedTypes
    constructor(
        startSegment: ULong,
        vararg segments: ULong
    ) : this(
        listOf(
            startSegment,
            *segments.toTypedArray()
        ).map {
            SdJwtTypeMetadataClaimInformationPathSegmentIndex(it)
        }
    )

    constructor(
        startSegment: String,
        vararg segments: String
    ) : this(
        listOf(
            startSegment,
            *segments
        ).map {
            SdJwtTypeMetadataClaimInformationPathSegmentName(it)
        }
    )

    operator fun plus(
        other: List<SdJwtTypeMetadataClaimInformationPathSegment?>
    ) = SdJwtTypeMetadataClaimInformationPath(this.segments + other)

    operator fun plus(
        segment: SdJwtTypeMetadataClaimInformationPathSegment?
    ) = SdJwtTypeMetadataClaimInformationPath(this.segments + segment)

    operator fun plus(index: ULong) = this + SdJwtTypeMetadataClaimInformationPathSegmentIndex(index)

    operator fun plus(name: String) = this + SdJwtTypeMetadataClaimInformationPathSegmentName(name)

    class SegmentSerializer : KSerializer<SdJwtTypeMetadataClaimInformationPathSegment?> {
        private val delegate = JsonPrimitive.Companion.serializer()
        override val descriptor: SerialDescriptor
            get() = SerialDescriptor(
                original = delegate.descriptor,
                serialName = SegmentSerializer::class.qualifiedName!!
            )

        override fun serialize(
            encoder: Encoder,
            value: SdJwtTypeMetadataClaimInformationPathSegment?
        ) {
            when (value) {
                is SdJwtTypeMetadataClaimInformationPathSegmentIndex -> encoder.encodeLong(value.ulong.toLong())
                is SdJwtTypeMetadataClaimInformationPathSegmentName -> encoder.encodeString(value.string)
                null -> encoder.encodeNull()
            }
        }

        override fun deserialize(decoder: Decoder): SdJwtTypeMetadataClaimInformationPathSegment? {
            require(decoder is JsonDecoder) {
                "Expected decoder to be JsonDecoder, but was $decoder"
            }
            val jsonElement = decoder.decodeJsonElement().jsonPrimitive
            require(jsonElement.isString || jsonElement.booleanOrNull == null) {
                "Expected content to be a string, `null` or a non-negative integer, but was: $jsonElement"
            }

            return when {
                jsonElement.isString -> SdJwtTypeMetadataClaimInformationPathSegmentName(jsonElement.content)
                jsonElement == JsonNull -> null
                else -> {
                    val long = jsonElement.long
                    require(long >= 0) {
                        "Expected content to be a string, `null` or a non-negative integer, but was: $jsonElement"
                    }
                    require(long <= Int.MAX_VALUE) {
                        "Expected path index to fit in a Kotlin list index (0..${Int.MAX_VALUE}), but was: $jsonElement"
                    }
                    SdJwtTypeMetadataClaimInformationPathSegmentIndex(long.toULong())
                }
            }
        }
    }

    override fun toString() = joinToString(", ", prefix="[", postfix = "]")
}
