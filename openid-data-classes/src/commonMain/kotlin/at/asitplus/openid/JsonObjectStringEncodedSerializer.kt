package at.asitplus.openid

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer

class JsonObjectStringEncodedSerializer<T>(
    val serializer: KSerializer<T>
) : KSerializer<T> by TransformingSerializerTemplate<T, String>(
    parent = String.serializer(),
    encodeAs = {
        joseCompliantSerializer.encodeToString(serializer, it)
    },
    decodeAs = {
        joseCompliantSerializer.decodeFromString(serializer, it)
    }
)