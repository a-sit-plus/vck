package at.asitplus.wallet.lib.data.rfc3986

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.ktor.http.Url
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer

object KtorUrlSerializer : KSerializer<Url> by TransformingSerializerTemplate<Url, String>(
    parent = String.serializer(),
    encodeAs = {
        it.toString()
    },
    decodeAs = {
        Url(it)
    }
)