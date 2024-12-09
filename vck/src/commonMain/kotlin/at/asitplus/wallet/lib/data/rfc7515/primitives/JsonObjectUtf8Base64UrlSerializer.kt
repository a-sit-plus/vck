package at.asitplus.wallet.lib.data.rfc7515.primitives

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.third_party.kotlin.decodeBase64UrlString
import at.asitplus.wallet.lib.third_party.kotlin.encodeBase64Url
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject

object JsonObjectUtf8Base64UrlSerializer : TransformingSerializerTemplate<JsonObject, ByteArray>(
    parent = ByteArraySerializer(),
    encodeAs = {
        vckJsonSerializer.encodeToString(it).encodeBase64Url().encodeToByteArray()
    },
    decodeAs = {
        vckJsonSerializer.decodeFromString<JsonObject>(it.decodeToString().decodeBase64UrlString())
    }
)