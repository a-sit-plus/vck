package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.builtins.serializer

object CompactApplicationMediaTypeSerializer : TransformingSerializerTemplate<String, String>(
    parent = String.serializer(),
    encodeAs = {
        val compressedPrefix = "application/"
        val substringAfter = it.substring(compressedPrefix.length)
        if(it.startsWith( compressedPrefix) && !substringAfter.contains('/')) {
            substringAfter
        } else it
    },
    decodeAs = {
        if(it.count { it == '/' } == 1) {
            "application/$it"
        } else it
    }
)