package at.asitplus.openid.dcql

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class DCQLSdJwtCredentialMetadataAndValidityConstraints(
    /**
     * OID4VP draft 23: vct_values: OPTIONAL. An array of strings that specifies allowed values for
     * the type of the requested Verifiable Credential. All elements in the array MUST be valid
     * type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc]. The Wallet MAY return credentials
     * that inherit from any of the specified types, following the inheritance logic defined in
     * [I-D.ietf-oauth-sd-jwt-vc].
     */
    @SerialName(SerialNames.VCT_VALUES)
    val vctValues: List<String>?
) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val VCT_VALUES = "vct_values"
    }
}