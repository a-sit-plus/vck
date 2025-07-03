package at.asitplus.openid

import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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

    fun serialize() = odcJsonSerializer.encodeToString(this)

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
        fun deserialize(it: String) = catching {
            odcJsonSerializer.decodeFromString<AuthnRequestSingleClaim>(it)
        }
    }

}

