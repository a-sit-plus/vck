package at.asitplus.rqes

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CscCredentialListResponse(
    /**
     * One or more credentialID(s) associated with the provided or implicit userID.
     */
    @SerialName("credentialIDs")
    val credentialIDs: List<String>,

    /**
     * If the credentialInfo parameter is not “true”,
     * this value SHALL NOT be returned.
     */
    @SerialName("credentialInfos")
    val credentialInfos: List<CredentialInfo>? = null,

    /**
     * This value SHALL be returned true when the input parameter “onlyValid”
     * was true, and the RSSP supports this feature, i.e. the RSSP only returns
     * credentials which can be used for signing.
     * If the values is false or the output parameter is omitted, then the list may
     * contain credentials which cannot be used for signing.
     */
    @SerialName("onlyValid")
    val onlyValid: Boolean? = null,
)