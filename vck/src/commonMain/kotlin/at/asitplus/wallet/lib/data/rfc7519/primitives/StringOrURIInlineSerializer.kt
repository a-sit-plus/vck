package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object StringOrURIInlineSerializer : TransformingSerializerTemplate<StringOrURI, String>(
    parent = String.serializer(),
    encodeAs = {
        it.value
    },
    decodeAs = {
        StringOrURI(it)
    }
)