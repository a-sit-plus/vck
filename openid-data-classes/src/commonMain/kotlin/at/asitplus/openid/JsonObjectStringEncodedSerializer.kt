package at.asitplus.openid

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer

class JsonObjectStringEncodedSerializer<T>(
    val serializer: KSerializer<T>
) : KSerializer<T> by TransformingSerializerTemplate<T, String>(
    parent = String.serializer(),
    encodeAs = {
        odcJsonSerializer.encodeToString(serializer, it)
    },
    decodeAs = {
        odcJsonSerializer.decodeFromString(serializer, it)
    }
)