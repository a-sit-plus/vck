package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Holds a deserialized [OidcUserInfo] as well as a [JsonObject] with other properties,
 * that could not been parsed into our data class [OidcUserInfo].
 * Will be used as a container to represent an authenticated user during the issuing process.
 */
@Serializable
data class OidcUserInfoExtended(
    val userInfo: OidcUserInfo,
    val jsonObject: JsonObject,
) {
    constructor(userInfo: OidcUserInfo) : this(
        userInfo,
        joseCompliantSerializer.encodeToJsonElement(userInfo) as JsonObject
    )

    companion object {
        fun deserialize(it: String): KmmResult<OidcUserInfoExtended> =
            catching {
                val jsonObject = joseCompliantSerializer.decodeFromString<JsonObject>(it)
                val userInfo = joseCompliantSerializer.decodeFromJsonElement<OidcUserInfo>(jsonObject)
                OidcUserInfoExtended(userInfo, jsonObject)
            }

        fun fromJsonObject(it: JsonObject): KmmResult<OidcUserInfoExtended> =
            catching {
                val userInfo = joseCompliantSerializer.decodeFromJsonElement<OidcUserInfo>(it)
                OidcUserInfoExtended(userInfo, it)
            }

        fun fromOidcUserInfo(userInfo: OidcUserInfo): KmmResult<OidcUserInfoExtended> =
            catching {
                OidcUserInfoExtended(userInfo, joseCompliantSerializer.encodeToJsonElement(userInfo) as JsonObject)
            }

    }
}