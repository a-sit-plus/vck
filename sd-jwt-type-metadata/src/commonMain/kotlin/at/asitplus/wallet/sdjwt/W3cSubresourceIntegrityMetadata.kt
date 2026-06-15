package at.asitplus.wallet.sdjwt

import at.asitplus.csp2.ContentSecurityPolicyBase64String
import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHash
import at.asitplus.csp2.ContentSecurityPolicySourceExpressionHashAlgorithm
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.jvm.JvmInline

/**
 * The value MUST be an "integrity metadata" string as defined in Section 3 of [W3C.SRI]. If an integrity property is
 * present for a particular claim, the Consumer of the respective document MUST verify the integrity of the retrieved
 * document as defined in Section 3.3.5 of [W3C.SRI].
 *
 * This metadata MUST be encoded in the same format as the hash-source (without the single quotes) in section 4.2 of the Content Security Policy Level 2 specification.
 * https://www.w3.org/TR/2016/REC-SRI-20160623/#integrity-metadata
 */
@Serializable(with = W3cSubresourceIntegrityMetadata.InlineSerializer::class)
@JvmInline
value class W3cSubresourceIntegrityMetadata(
    val expression: ContentSecurityPolicySourceExpressionHash
) {
    constructor(string: String): this(
        ContentSecurityPolicySourceExpressionHash.Companion("'$string'")
    )

    constructor(
        algorithm: ContentSecurityPolicySourceExpressionHashAlgorithm,
        hashValue: ByteArray,
    ): this(
        ContentSecurityPolicySourceExpressionHash(
            algorithm = algorithm,
            hashValue = ContentSecurityPolicyBase64String(hashValue)
        )
    )

    val algorithm
        get() = expression.algorithm

    val byteArray
        get() = expression.hashValue.byteArray

    val string
        get() = expression.string.removePrefix("'").removeSuffix("'")

    override fun toString() = string

    class InlineSerializer : KSerializer<W3cSubresourceIntegrityMetadata> {
        override val descriptor: SerialDescriptor
            get() = PrimitiveSerialDescriptor(
                serialName = InlineSerializer::class.qualifiedName!!,
                kind = PrimitiveKind.STRING,
            )

        override fun serialize(
            encoder: Encoder,
            value: W3cSubresourceIntegrityMetadata
        ) {
            encoder.encodeString(value.toString())
        }

        override fun deserialize(decoder: Decoder) = W3cSubresourceIntegrityMetadata(
            decoder.decodeString()
        )
    }
}