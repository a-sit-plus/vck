package at.asitplus.csp2

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = ContentSecurityPolicySourceExpressionHash.StringSerializer::class)
data class ContentSecurityPolicySourceExpressionHash(
    val algorithm: ContentSecurityPolicySourceExpressionHashAlgorithm,
    val hashValue: ContentSecurityPolicyBase64String,
): ContentSecurityPolicySourceExpression {
    val string
        get() = """'$algorithm-$hashValue'"""
    override fun toString() = string

    companion object {
        // 1*( ALPHA / DIGIT / "+" / "/" )*2( "=" )
        const val REGEX = "'(sha256|sha384|sha512)-([a-zA-Z0-9+/]+={0,2})'"
        operator fun invoke(string: String): ContentSecurityPolicySourceExpressionHash {
            require(string.startsWith("'")) {
                "Expected hash-source to start with `'`, but got $string"
            }
            require(string.endsWith("'")) {
                "Expected hash-source to end with `'`, but got $string"
            }
            val content = string.trim('\'').split('-')
            require(content.size == 2) {
                "Expected hash-source to consist of 2 '-'-separated parts, but got ${content.size} in `$string`."
            }
            val (algorithm, value) = content
            return ContentSecurityPolicySourceExpressionHash(
                algorithm = try {
                    ContentSecurityPolicySourceExpressionHashAlgorithm.valueOf(algorithm)
                } catch (_: Throwable) {
                    throw IllegalArgumentException("Expected algorithm identifier to be either of ${ContentSecurityPolicySourceExpressionHashAlgorithm.entries}, but got `$algorithm`.")
                },
                hashValue = ContentSecurityPolicyBase64String(value),
            )
        }
    }

    class StringSerializer : KSerializer<ContentSecurityPolicySourceExpressionHash> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = StringSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: ContentSecurityPolicySourceExpressionHash
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder) = ContentSecurityPolicySourceExpressionHash(
            decoder.decodeString()
        )
    }
}