package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Holds a deserialized [OidcUserInfo] as well as a [JsonObject] with other properties,
 * that could not been parsed.
 */
data class OidcUserInfoExtended(
    val userInfo: OidcUserInfo,
    val jsonObject: JsonObject,
) {
    companion object {
        fun deserialize(it: String): KmmResult<OidcUserInfoExtended> =
            runCatching {
                val jsonObject = jsonSerializer.decodeFromString<JsonObject>(it)
                val userInfo = jsonSerializer.decodeFromJsonElement<OidcUserInfo>(jsonObject)
                OidcUserInfoExtended(userInfo, jsonObject)
            }.wrap()

        fun fromOidcUserInfo(userInfo: OidcUserInfo): KmmResult<OidcUserInfoExtended> =
            runCatching {
                OidcUserInfoExtended(userInfo, jsonSerializer.encodeToJsonElement(userInfo) as JsonObject)
            }.wrap()
    }
}