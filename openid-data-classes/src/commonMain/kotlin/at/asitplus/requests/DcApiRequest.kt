package at.asitplus.requests

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Abstract base class for requests received via the Digital Credentials API.
 *
 * Other Members can only be specified after [PreviewDcApiRequest] is deleted
 */
//TODO WIP
@Serializable
sealed interface DcApiRequest : AuthenticationRequest {
    @SerialName("credentialId")
    val credentialId: String
//    @SerialName("callingPackageName")
//    val callingPackageName: String
//    @SerialName("callingOrigin")
//    val callingOrigin: String
}