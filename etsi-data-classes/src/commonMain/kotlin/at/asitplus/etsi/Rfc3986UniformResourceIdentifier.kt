package at.asitplus.etsi

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = Rfc3986UniformResourceIdentifier.InlineSerializer::class)
data class Rfc3986UniformResourceIdentifier(
    val schemeName: Rfc3986UriSchemeName,
    val authority: Rfc3986Authority? = null,
    val path: Rfc3986UriPath,
    val query: Rfc3986UriQuery? = null,
    val fragment: Rfc3986UriFragment? = null,
) {
    init {
        if (authority != null) {
            // All of these are necessary since Rfc3986UriPathAbsoluteOrEmpty allows for the first segment to be empty
            require(path is Rfc3986UriPathAbsoluteOrEmpty || path is Rfc3986UriPathEmpty || path is Rfc3986UriPathAbsolute) {
                "Expected path after authority to be either absolute or empty, but got `$path`."
            }
        }
    }

    override fun toString() = string

    val string: String by lazy {
        listOfNotNull(
            "$schemeName:",
            authority?.toString(true),
            path.toString(),
            query?.let { "?$it" },
            fragment?.let { "#$it" },
        ).joinToString("")
    }

    companion object {
        operator fun invoke(string: String): Rfc3986UniformResourceIdentifier {
            val partRegex = Regex("""^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?""")
            val match = partRegex.matchEntire(string)
            require(match != null) {
                "Expected string to be a valid URI, but tokenization itself failed already."
            }

            val scheme = match.groups[2]?.value ?: throw IllegalArgumentException(
                "Expected URI to contain a scheme, but none was found."
            )
            val authority = match.groups[4]?.value
            val path = match.groups[5]?.value ?: throw IllegalArgumentException(
                "Expected URI to contain a path, but none was found."
            )
            val query = match.groups[7]?.value
            val fragment = match.groups[9]?.value

//            val schemeSeparatorIndex = string.indexOf(':')
//            val schemeName = Rfc3986UriSchemeName(string.substring(0..<schemeSeparatorIndex))
//
//            val authoritySeparatorIndex = string.substring(schemeSeparatorIndex + 1).takeIf {
//                it.startsWith("//")
//            }?.let {
//                it.indexOfAny(
//                    charArrayOf('/', '?', '#'),
//                    startIndex = 2, //
//                ).takeIf {
//                    it != -1
//                } ?: it.length
//            }
//            val authority = authoritySeparatorIndex?.let {
//                Rfc3986Authority(string.substring(schemeSeparatorIndex + 3..<it))
//            }
//            // The path is terminated
//            //   by the first question mark ("?") or number sign ("#") character, or
//            //   by the end of the URI.
//            val pathSeparatorIndex = string.indexOfAny(
//                charArrayOf('?', '#'),
//                startIndex = (authoritySeparatorIndex ?: schemeSeparatorIndex) + 1,
//            )

            return Rfc3986UniformResourceIdentifier(
                schemeName = Rfc3986UriSchemeName(scheme),
                authority = authority?.let {
                    Rfc3986Authority(it)
                },
                path = if (authority != null) {
                    Rfc3986UriPathAbsoluteOrEmpty(path)
                } else {
                    Rfc3986UriPath(path)
                },
                query = query?.let(::Rfc3986UriQuery),
                fragment = fragment?.let(::Rfc3986UriFragment),
            )
        }
    }

    class InlineSerializer : KSerializer<Rfc3986UniformResourceIdentifier> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: Rfc3986UniformResourceIdentifier
        ) {
            encoder.encodeString(value.string)
        }

        override fun deserialize(decoder: Decoder) = Rfc3986UniformResourceIdentifier(
            decoder.decodeString()
        )
    }
}

