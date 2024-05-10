package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.iso.ElementValue
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

object CredentialToJsonConverter {
    // in openid4vp, the claims to be presented are described using a JSONPath, so compiling this to a JsonElement seems reasonable
    fun toJsonElement(credential: SubjectCredentialStore.StoreEntry): JsonElement {
        return when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> {
                buildJsonObject {
                    put("type", JsonPrimitive(credential.scheme.vcType))
                    jsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject).jsonObject.entries.forEach {
                        put(it.key, it.value)
                    }
                    // TODO: Remove the rest here when there is a clear specification on how to encode vc credentials
                    //  This may actually depend on the presentation context, so more information may be required
                    put("vc", buildJsonArray {
                        add(jsonSerializer.encodeToJsonElement(credential.vc.vc.credentialSubject))
                    })
                }
            }

            is SubjectCredentialStore.StoreEntry.SdJwt -> {
                val pairs = credential.disclosures.map {
                    it.value?.let {
                        it.claimName to when (val value = it.claimValue) {
                            is Boolean -> JsonPrimitive(value)
                            is Number -> JsonPrimitive(value)
                            else -> JsonPrimitive(it.claimValue.toString())
                        }
                    }
                }.filterNotNull().toMap()
                buildJsonObject {
                    put("type", JsonPrimitive(credential.scheme.vcType))
                    pairs.forEach {
                        put(it.key, it.value)
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

    private fun ElementValue.toJsonElement(): JsonElement = this.boolean?.let {
        JsonPrimitive(it) }
        ?: this.string?.let {
            JsonPrimitive(it) }
        ?: this.bytes?.let {
            buildJsonArray {
                it.forEach { this.add(JsonPrimitive(it.toInt())) }
            }
        } ?: this.drivingPrivilege?.let { drivingPrivilegeArray ->
            buildJsonArray {
                drivingPrivilegeArray.forEach {
                    this.add(jsonSerializer.encodeToJsonElement(it))
                }
            }
        } ?: this.date?.let {
            JsonPrimitive(it.toString())
        } ?: JsonNull
}