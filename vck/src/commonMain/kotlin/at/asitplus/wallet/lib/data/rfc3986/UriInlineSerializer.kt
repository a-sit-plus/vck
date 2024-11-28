package at.asitplus.wallet.lib.data.rfc3986

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer

object UriInlineSerializer : TransformingSerializerTemplate<UniformResourceIdentifier, String>(
    parent = String.serializer(),
    encodeAs = {
        it.value
    },
    decodeAs = {
        UniformResourceIdentifier(it)
    }
)