package at.asitplus.wallet.lib.data

import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.wallet.lib.agent.SdJwtValidator
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.*

object CredentialToJsonConverter {
    // in openid4vp, the claims to be presented are described using a JSONPath, so compiling this to a JsonElement seems reasonable
    fun toJsonElement(credential: SubjectCredentialStore.StoreEntry): JsonElement {
        return when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> {
                buildJsonObject {
                    put("type", JsonPrimitive(credential.scheme.vcType))
                    vckJsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject).jsonObject.entries.forEach {
                        put(it.key, it.value)
                    }
                    // TODO: Remove the rest here when there is a clear specification on how to encode vc credentials
                    //  This may actually depend on the presentation context, so more information may be required
                    put("vc", buildJsonArray {
                        add(vckJsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject))
                    })
                }
            }

            is SubjectCredentialStore.StoreEntry.SdJwt -> {
                val reconstructed = SdJwtSigned.parse(credential.vcSerialized)
                    ?.let { SdJwtValidator(it).reconstructedJsonObject }
                val simpleDisclosureMap = credential.disclosures.map { entry ->
                    entry.value?.let { it.claimName to it.claimValue }
                }.filterNotNull().toMap()


                buildJsonObject {
                    put("vct", JsonPrimitive(credential.scheme.sdJwtType ?: credential.scheme.vcType))
                    reconstructed?.forEach {
                        put(it.key, it.value)
                    } ?: simpleDisclosureMap.forEach { pair ->
                        pair.key?.let { put(it, pair.value) }
                    }
                }
            }

            is SubjectCredentialStore.StoreEntry.Iso -> {
                buildJsonObject {
                    credential.issuerSigned.namespaces?.forEach {
                        put(it.key, buildJsonObject {
                            it.value.entries.forEach { signedItem ->
                                put(
                                    signedItem.value.elementIdentifier,
                                    signedItem.value.elementValue.toJsonElement()
                                )
                            }
                        })
                    }
                }
            }
        }
    }

    private fun Any.toJsonElement(): JsonElement = when (this) {
        is Boolean -> JsonPrimitive(this)
        is String -> JsonPrimitive(this)
        is ByteArray -> JsonPrimitive(encodeToString(Base64Strict))
        is LocalDate -> JsonPrimitive(this.toString())
        is Array<*> -> buildJsonArray { filterNotNull().forEach { add(it.toJsonElement()) } }
        else -> JsonCredentialSerializer.encode(this) ?: JsonNull
    }
}