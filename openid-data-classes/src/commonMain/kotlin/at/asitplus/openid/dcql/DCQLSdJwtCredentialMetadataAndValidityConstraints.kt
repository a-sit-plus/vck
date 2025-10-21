package at.asitplus.openid.dcql

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class DCQLSdJwtCredentialMetadataAndValidityConstraints(
    /**
     * OID4VP 1.0: vct_values: REQUIRED. An array of strings that specifies allowed values for
     * the type of the requested Verifiable Credential. All elements in the array MUST be valid
     * type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc]. The Wallet MAY return credentials
     * that inherit from any of the specified types, following the inheritance logic defined in
     * [I-D.ietf-oauth-sd-jwt-vc].
     */
    @SerialName(SerialNames.VCT_VALUES)
    val vctValues: List<String>
) : DCQLCredentialMetadataAndValidityConstraints {
    object SerialNames {
        const val VCT_VALUES = "vct_values"
    }

    fun validate(actualCredentialType: String?): KmmResult<Unit> = catching {
        if (actualCredentialType !in vctValues) {
            throw IllegalArgumentException("Incompatible SD-JWT document type")
        }
    }
}

