package at.asitplus.openid.dcql

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DCQLTrustedAuthority(
    /**
     * OpenID4VP 1.0: REQUIRED. A string uniquely identifying the type of information about the
     * issuer trust framework. Types defined by this specification are listed below.
     */
    @SerialName(SerialNames.TYPE)
    val type: DCQLTrustedAuthorityType,

    /**
     * OpenID4VP 1.0: REQUIRED. A non-empty array of strings, where each string (value) contains
     * information specific to the used Trusted Authorities Query type that allows the
     * identification of an issuer, a trust framework, or a federation that an issuer belongs to.
     */
    @SerialName(SerialNames.VALUES)
    val values: List<String>,
) {
    object SerialNames {
        const val TYPE = "type"
        const val VALUES = "values"
    }

    fun validate() {
        require(values.isNotEmpty())
    }
}