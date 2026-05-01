package at.asitplus.rfc

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986AuthorityHostIPvFuture.InlineSerializer::class)
data class Rfc3986AuthorityHostIPvFuture(
    val string: String,
): Rfc3986AuthorityHost {
    @Transient
    private val summary = validate()

    private fun validate(): Pair<ULong, CaseInsensitiveString> {
        val start = string.firstOrNull()
        require(start != null && start in "vV") {
            "Expected future ip version literals to start with a version indicator, but got `$string`"
        }
        val dataSeparatorIndex = string.indexOf('.').takeIf {
            it != -1
        }
        require(dataSeparatorIndex != null) {
            "Expected future ip version literals separate version from data using `.`, but did not find `.` in `$string`."
        }
        val version = string.substring(1, dataSeparatorIndex)
        require(version.isNotEmpty()) {
            "Expected future ip version literals to contain a non-empty version number, but got `$string`."
        }
        version.forEachIndexed { index, ch ->
            require(Rfc3986Grammar.isHexDigit(ch)) {
                "Expected future ip version literals to denote their version number in hexadecimal digits, but got `$ch` at index $index in `$string`."
            }
        }
        val data = string.substring(dataSeparatorIndex + 1)
        require(data.isNotEmpty()) {
            "Expected future ip version literals to carry a non-empty data sequence, but got `$string`."
        }
        Rfc3986Grammar.run {
            data.forEachIndexed { index, ch ->
                require(isUnreserved(ch) || isSubcomponentDelimiter(ch) || ch == ':') {
                    "Expected future ip version literals to denote their data squence using characters that are either unreserved, sub-delims or \":\", but got `$ch` at index $index in `$string`."
                }
            }
        }
        return version.toULong(16) to CaseInsensitiveString(data)
    }

    class InlineSerializer : KSerializer<Rfc3986AuthorityHostIPvFuture> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986AuthorityHostIPvFuture
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder) = Rfc3986AuthorityHostIPvFuture(decoder.decodeString())
    }

    /**
     * This is the representation when serializing as part of a URI.
     * Since this is our default use case, we do it this way.
     */
    override fun toString() = "[$string]"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Rfc3986AuthorityHostIPvFuture

        if (summary != other.summary) return false

        return true
    }

    override fun hashCode(): Int {
        val result = summary.hashCode()
        return result
    }
}