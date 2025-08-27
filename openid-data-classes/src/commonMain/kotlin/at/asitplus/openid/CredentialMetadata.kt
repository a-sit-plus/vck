package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

/**
 * OID4VCI: Object containing information relevant to the usage and display of issued Credentials. Credential
 * Format-specific mechanisms can overwrite the information in this object to convey Credential metadata.
 * Format-specific mechanisms, such as SD-JWT VC display metadata are always preferred by the Wallet over the
 * information in this object, which serves as the default fallback.
 */
@Serializable
data class CredentialMetadata(
    /**
     * OID4VCI: Issuer Metadata:
     * A claims description object as used in the Credential Issuer metadata is an object used to describe how a certain
     * claim in the Credential is displayed to the End-User. It is used in the claims parameter in the Credential Issuer
     * metadata defined in Appendix A.
     *
     * OID4VCI: Authorization Details:
     * A claims description object as used in authorization details is an object that defines the requirements for the
     * claims that the Wallet requests to be included in the Credential.
     */
    @SerialName("claims")
    val claimDescription: Set<ClaimDescription>? = null,

    /**
     * OID4VCI: OPTIONAL. A non-empty array of objects, where each object contains the display properties of the
     * supported Credential for a certain language.
     */
    @SerialName("display")
    val display: Set<DisplayProperties>? = null,
)
