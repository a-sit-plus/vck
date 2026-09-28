package at.asitplus.csc.datamodel.serializers

import at.asitplus.csc.datamodel.documents.SignatureCreationRequestContent
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

internal val DOCUMENT_CONTENT_KEYS = setOf(
    "label", "document", "documentType", "circumstantialData", "access", "href", "checksum", "hashes",
)
internal val ADES_KEYS = setOf(
    "signature_format",
    "conformance_level",
    "signed_envelope_property",
    "signed_props",
    "referenceUri",
)
internal val SIGNING_KEYS = setOf("signAlgo", "signAlgoParams")
internal const val SIGNATURE_QUALIFIER = "signatureQualifier"
internal const val RESPONSE_URI = "responseURI"

internal fun <T> MutableMap<String, JsonElement>.addObject(json: Json, serializer: KSerializer<T>, value: T) {
    putAll(json.encodeToJsonElement(serializer, value).jsonObject)
}

internal fun <T> Json.decodeFiltered(
    serializer: KSerializer<T>,
    properties: JsonObject,
    keys: Set<String>,
): T = decodeFromJsonElement(serializer, JsonObject(properties.filterKeys(keys::contains)))

internal fun JsonObject.decodeCreationDocument(json: Json): SignatureCreationRequestContent =
    json.decodeFiltered(SignatureCreationRequestContent.serializer(), this, DOCUMENT_CONTENT_KEYS)

internal fun JsonObject.decodeRequestDocument(json: Json): SignatureRequestContent =
    json.decodeFiltered(SignatureRequestContent.serializer(), this, DOCUMENT_CONTENT_KEYS)

internal fun Json.encodeCreationDocument(document: SignatureCreationRequestContent): JsonObject =
    encodeToJsonElement(SignatureCreationRequestContent.serializer(), document).jsonObject

internal fun Json.encodeRequestDocument(document: SignatureRequestContent): JsonObject =
    encodeToJsonElement(SignatureRequestContent.serializer(), document).jsonObject

internal fun kotlinx.serialization.encoding.Encoder.requireJsonEncoder(): JsonEncoder = this as? JsonEncoder
    ?: throw SerializationException("CSC data-model objects can only be serialized as JSON")

internal fun kotlinx.serialization.encoding.Decoder.requireJsonDecoder(): JsonDecoder = this as? JsonDecoder
    ?: throw SerializationException("CSC data-model objects can only be deserialized from JSON")
