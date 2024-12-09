package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64UrlString
import at.asitplus.wallet.lib.third_party.kotlin.encodeBase64Url
import kotlinx.serialization.builtins.ByteArraySerializer

object StringUtf8Base64UrlSerializer : TransformingSerializerTemplate<String, ByteArray>(
    parent = ByteArraySerializer(),
    encodeAs = {
        it.encodeBase64Url().encodeToByteArray()
    },
    decodeAs = {
        it.decodeToString().decodeBase64UrlString()
    }
)

