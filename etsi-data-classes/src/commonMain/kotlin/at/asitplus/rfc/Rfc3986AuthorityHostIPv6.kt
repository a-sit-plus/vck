package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.require

@Serializable(with = Rfc3986AuthorityHostIPv6.InlineSerializer::class)
data class Rfc3986AuthorityHostIPv6(
    val string: String,
) : Rfc3986AuthorityHost {
    /**
     * parts such that the string represents part0:part1:…:part7
     */
    @Transient
    val parts = splitToParts().also { reconstructedParts ->
        require(reconstructedParts.size == PARTS_TOTAL) {
            "Expected an IPv6 address to contain exactly 8 parts, but got ${reconstructedParts.size} in `$string`."
        }
    }

    companion object {
        const val PARTS_TOTAL = 8
    }

    fun toConciseRepresentation() = combineZerosBetween?.let { combineZerosBetween ->
        parts.subList(0, combineZerosBetween.first).joinToString(":") {
            it.toString(16)
        } + "::" + parts.subList(combineZerosBetween.second + 1, parts.size).joinToString(":") {
            it.toString(16)
        }
    } ?: parts.joinToString(":") {
        it.toString(16)
    }

    class InlineSerializer : KSerializer<Rfc3986AuthorityHostIPv6> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986AuthorityHostIPv6
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder) = Rfc3986AuthorityHostIPv6(decoder.decodeString())
    }

    class ConciseSerializer : KSerializer<Rfc3986AuthorityHostIPv6> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = ConciseSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986AuthorityHostIPv6
        ) {
            encoder.encodeString(value.toConciseRepresentation())
        }

        override fun deserialize(decoder: Decoder) = Rfc3986AuthorityHostIPv6(decoder.decodeString())
    }

    /**
     * This is the representation when serializing as part of a URI.
     * Since this is our default use case, we do it this way.
     */
    override fun toString() = "[$string]"

    // finding most efficient representation for skipping parts
    private val combineZerosBetween by lazy {
        parts.runningFoldIndexed(null as Pair<Int, Int>?) { index, acc, it ->
            if (it == 0u.toUShort()) {
                (acc?.first ?: index) to index
            } else {
                null
            }
        }.maxBy {
            it?.let {
                it.second - it.first + 1
            } ?: 0
        }
    }

    private fun splitToParts(): List<UShort> {
        val parts = string.split("::").map {
            it.split(":").filter {
                it.isNotEmpty()
            }
        }

        val firstParts = when (parts.size) {
            2 -> parts.first().map {
                it.toHexPart()
            }

            1 -> listOf()
            else -> throw IllegalArgumentException(
                """Expected IPv6 address to consist of at most 1 `::`-separator, but got ${parts.size - 1} in `$string`."""
            )
        }

        val afterDoubleColon = parts.last()
        val middleParts = afterDoubleColon.dropLast(1).map {
            it.toHexPart()
        }

        val lastParts = afterDoubleColon.lastOrNull()?.let {
            if (it.contains(".")) {
                val ipv4 = Rfc3986AuthorityHostIPv4(it)
                ipv4.parts.chunked(2).map { (first, second) ->
                    (first.toUInt().shl(8) + second).toUShort()
                }
            } else {
                listOf(
                    it.toHexPart()
                )
            }
        } ?: listOf()

        val missingParts = PARTS_TOTAL - firstParts.size - middleParts.size - lastParts.size

        val reconstructedParts = listOf(
            firstParts,
            List(missingParts) {
                0.toUShort()
            },
            middleParts,
            lastParts,
        ).flatten()

        return reconstructedParts
    }

    private fun String.toHexPart(): UShort {
        require(length in 1..4) {
            "Expected IPv6 hex segments to consist of 1 to 4 characters, but got $length at `$this`."
        }
        return toUShort(16)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc3986AuthorityHostIPv6

        if (parts != other.parts) return false

        return true
    }

    override fun hashCode(): Int {
        val result = parts.hashCode()
        return result
    }
}