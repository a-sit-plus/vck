package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

object DCQLCredentialSetQueryPurposeSerializer : KSerializer<DCQLCredentialSetQueryPurpose> by TransformingSerializerTemplate<DCQLCredentialSetQueryPurpose, JsonElement>(
    parent = JsonElement.serializer(),
    encodeAs = {
        when (it) {
            is DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeString -> JsonPrimitive(it.string)
            is DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeObject -> it.jsonObject
            is DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeDouble -> JsonPrimitive(it.double)
            is DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeLong -> JsonPrimitive(it.long)
        }
    },
    decodeAs = {
        when (it) {
            is JsonArray -> throw IllegalArgumentException("Value must not be an array.")
            is JsonObject -> DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeObject(it)
            is JsonPrimitive -> it.longOrNull?.let {
                DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeLong(it)
            } ?: it.doubleOrNull?.let {
                DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeDouble(it)
            } ?: if (it.isString) {
                DCQLCredentialSetQueryPurpose.DCQLCredentialSetQueryPurposeString(it.content)
            } else {
                throw IllegalArgumentException("Value must be a string, a number or an object.")
            }
        }
    }
)