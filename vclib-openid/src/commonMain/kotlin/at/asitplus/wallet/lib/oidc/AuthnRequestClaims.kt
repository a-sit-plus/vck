package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class AuthnRequestClaims(
    /**
     * OIDC: OPTIONAL. Requests that the listed individual Claims be returned in the ID Token. If present, the listed
     * Claims are being requested to be added to the default Claims in the ID Token. If not present, the default
     * ID Token Claims are requested.
     */
    @SerialName("id_token")
    val idTokenMap: Map<String, AuthnRequestSingleClaim?>? = null,

    /**
     * OIDC: OPTIONAL. Requests that the listed individual Claims be returned from the UserInfo Endpoint. If present,
     * the listed Claims are being requested to be added to any Claims that are being requested using `scope` values.
     * If not present, the Claims being requested from the UserInfo Endpoint are only those requested using `scope`
     * values. When the `userinfo` member is used, the request MUST also use a `response_type` value that results in an
     * Access Token being issued to the Client for use at the UserInfo Endpoint.
     */
    @SerialName("userinfo")
    val userInfoMap: Map<String, AuthnRequestSingleClaim?>? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthnRequestClaims>(it)
        }.wrap()
    }

}

@Serializable
data class AuthnRequestSingleClaim(
    /**
     * OIDC: OPTIONAL. Indicates whether the Claim being requested is an Essential Claim. If the value is true, this
     * indicates that the Claim is an Essential Claim.
     */
    @SerialName("essential")
    val essential: Boolean? = null,

    /**
     * OIDC: OPTIONAL. Requests that the Claim be returned with a particular value.
     */
    @SerialName("value")
    val value: String? = null,

    /**
     * OIDC: OPTIONAL. Requests that the Claim be returned with one of a set of values, with the values appearing in
     * order of preference.
     */
    @SerialName("values")
    val values: Array<String>? = null,
) {

    fun serialize() = jsonSerializer.encodeToString(this)
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthnRequestSingleClaim

        if (essential != other.essential) return false
        if (value != other.value) return false
        if (values != null) {
            if (other.values == null) return false
            if (!values.contentEquals(other.values)) return false
        } else if (other.values != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = essential?.hashCode() ?: 0
        result = 31 * result + (value?.hashCode() ?: 0)
        result = 31 * result + (values?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthnRequestSingleClaim>(it)
        }.wrap()
    }

}

