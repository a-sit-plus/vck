package at.asitplus.wallet.lib.data.rfc7519.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonPrimitive

object NumericDateInlineSerializer : TransformingSerializerTemplate<NumericDate, Double>(
    parent = Double.serializer(),
    decodeAs = {
        NumericDate(it)
    },
    encodeAs = {
        it.secondsSinceEpoch
    },
)

