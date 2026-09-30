package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** CSC Data Model 1.0.0 section 8.3: Access methods for documents referenced by URI. */
@Serializable
sealed class AccessControlMethod {

    /**
     * In this case, no further authorization is needed to access a remote resource. This does not preclude the option
     * that the resource locator is secret, and access is thereby restricted to clients who know it.
     */
    @Serializable
    @SerialName("public")
    data object Public : AccessControlMethod()

    @Serializable
    @SerialName("OTP")
    data class OTP(
        /** CSC Data Model 1.0.0 section 8.3: One-time password used to retrieve the document. */
        @SerialName("oneTimePassword")
        val oneTimePassword: String
    ) : AccessControlMethod()

    @Serializable
    @SerialName("Basic_Auth")
    data object Basic : AccessControlMethod()

    @Serializable
    @SerialName("Digest_Auth")
    data object Digest : AccessControlMethod()

    @Serializable
    @SerialName("OAuth_20")
    data object Oauth2 : AccessControlMethod()
}
