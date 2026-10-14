package at.asitplus.etsi.relyingParty

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.jvm.JvmInline

/** An expected value of a [WrpClaim]: a string, an integer, or a boolean (ETSI TS 119 475 V1.2.1, B.2.10). */
@Serializable(with = WrpClaimValueSerializer::class)
sealed interface WrpClaimValue {
    @JvmInline
    value class Text(val value: String) : WrpClaimValue

    @JvmInline
    value class Integer(val value: Long) : WrpClaimValue

    @JvmInline
    value class Bool(val value: Boolean) : WrpClaimValue
}

/**
 * Serializes a [WrpClaimValue] as a string, an integer, or a boolean. A WRPRC in JWT format (JSON) may carry any of
 * them; without a generic CBOR element in kotlinx-serialization, the values of a WRPRC in CWT format can only be
 * decoded as strings.
 */
object WrpClaimValueSerializer : KSerializer<WrpClaimValue> {
    override val descriptor =
        PrimitiveSerialDescriptor("at.asitplus.etsi.relyingParty.WrpClaimValue", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: WrpClaimValue) {
        when (value) {
            is WrpClaimValue.Text -> encoder.encodeString(value.value)
            is WrpClaimValue.Integer -> encoder.encodeLong(value.value)
            is WrpClaimValue.Bool -> encoder.encodeBoolean(value.value)
        }
    }

    override fun deserialize(decoder: Decoder): WrpClaimValue = if (decoder is JsonDecoder) {
        val element = decoder.decodeJsonElement()
        when {
            element !is JsonPrimitive -> throw SerializationException("Invalid value of a claim: $element")
            element.isString -> WrpClaimValue.Text(element.content)
            element.booleanOrNull != null -> WrpClaimValue.Bool(element.booleanOrNull!!)
            element.longOrNull != null -> WrpClaimValue.Integer(element.longOrNull!!)
            else -> throw SerializationException("Invalid value of a claim: $element")
        }
    } else {
        WrpClaimValue.Text(decoder.decodeString())
    }
}
