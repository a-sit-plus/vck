package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.third_party.kotlin.encodeBase64Url
import kotlinx.serialization.builtins.serializer

object CompactJsonWebSignatureSerializer : TransformingSerializerTemplate<CompactJsonWebSignature, String>(
    parent = String.serializer(),
    encodeAs = {
        listOf(
            it.header,
            it.payload,
            it.signature,
        ).joinToString(".") {
            it.encodeBase64Url()
        }
    },
    decodeAs = {
        CompactJsonWebSignature.deserialize(it)
    }
)