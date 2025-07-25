package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.SdJwtDecoded
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

private const val SD_JWT_VC_TYPE = "vct"

/**
 * In OpenID4VP, the claims to be presented are described using a JSONPath, so compiling this to a JsonElement seems
 * reasonable.
 */
object CredentialToJsonConverter {

    /**
     * The result is used in [at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator.evaluateConstraintFieldMatches]
     */
    fun toJsonElement(credential: SubjectCredentialStore.StoreEntry): JsonElement = when (credential) {
        is SubjectCredentialStore.StoreEntry.Vc -> buildJsonObject {
            put("type", JsonPrimitive(credential.scheme?.vcType))
            val vcAsJsonElement = vckJsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject)
            vcAsJsonElement.jsonObject.entries.forEach {
                put(it.key, it.value)
            }
            // TODO: Remove the rest here when there is a clear specification on how to encode vc credentials
            //  This may actually depend on the presentation context, so more information may be required
            put("vc", buildJsonArray {
                add(vcAsJsonElement)
            })
        }

        is SubjectCredentialStore.StoreEntry.SdJwt -> {
            val sdJwtSigned = SdJwtSigned.parse(credential.vcSerialized)
            val payloadVc = sdJwtSigned?.getPayloadAsJsonObject()?.getOrNull()
            val reconstructed = sdJwtSigned?.let { SdJwtDecoded(it).reconstructedJsonObject }
            val simpleDisclosureMap = credential.disclosures.map { entry ->
                entry.value?.let { it.claimName to it.claimValue }
            }.filterNotNull().toMap()

            buildJsonObject {
                if (payloadVc?.get(SD_JWT_VC_TYPE) == null)
                    put(SD_JWT_VC_TYPE, JsonPrimitive(credential.scheme?.sdJwtType))
                payloadVc?.forEach {
                    put(it.key, it.value)
                }

                reconstructed?.forEach {
                    put(it.key, it.value)
                } ?: simpleDisclosureMap.forEach { pair ->
                    pair.key?.let { put(it, pair.value) }
                }
            }
        }

        is SubjectCredentialStore.StoreEntry.Iso -> buildJsonObject {
            credential.issuerSigned.namespaces?.forEach {
                put(it.key, buildJsonObject {
                    it.value.entries.map { it.value }.forEach { value ->
                        put(value.elementIdentifier, value.elementValue.toJsonElement())
                    }
                })
            }
        }
    }

    /**
     * Converts any value to a [JsonElement], to be used when serializing values into JSON structures.
     */
    fun Any.toJsonElement(): JsonElement = when (this) {
        is Boolean -> JsonPrimitive(this)
        is Number -> JsonPrimitive(this)
        is String -> JsonPrimitive(this)
        is ByteArray -> JsonPrimitive(encodeToString(Base64UrlStrict))
        is LocalDate -> JsonPrimitive(this.toString())
        is UByte -> JsonPrimitive(this)
        is UShort -> JsonPrimitive(this)
        is UInt -> JsonPrimitive(this)
        is ULong -> JsonPrimitive(this)
        is Collection<*> -> JsonArray(mapNotNull { it?.toJsonElement() }.toList())
        is Array<*> -> JsonArray(mapNotNull { it?.toJsonElement() }.toList())
        is JsonElement -> this
        else -> JsonCredentialSerializer.encode(this) ?: JsonPrimitive(toString())
    }
}

fun SelectiveDisclosureItem.Companion.fromAnyValue(salt: ByteArray, claimName: String?, claimValue: Any) =
    SelectiveDisclosureItem(salt, claimName, claimValue.toJsonElement())