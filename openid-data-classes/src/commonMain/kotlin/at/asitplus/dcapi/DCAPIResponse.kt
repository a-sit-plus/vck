package at.asitplus.dcapi

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@Serializable
data class DCAPIResponse(
    /**
     * ISO 18013-7 Annex-C:
     * response: Base64EncryptedResponse contains the cbor encoded EncryptedResponse as a
     * base64-url-without-padding string
     */
    @SerialName("response")
    @Serializable(with = EncryptedResponseBase64UrlSerializer::class)
    val response: EncryptedResponse,
)

object EncryptedResponseBase64UrlSerializer : TransformingSerializerTemplate<EncryptedResponse, String>(
    parent = String.serializer(),
    encodeAs = { coseCompliantSerializer.encodeToByteArray(it).encodeToString(Base64UrlStrict) },
    decodeAs = { coseCompliantSerializer.decodeFromByteArray<EncryptedResponse>(it.decodeToByteArray(Base64UrlStrict)) }
)