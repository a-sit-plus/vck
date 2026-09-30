package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** CSC Data Model 1.0.0 section 8.3: REQUIRED
 * Access method for a document referenced by URI; `type` is the required discriminator.
 */
@Serializable
sealed class AccessControlMethod {

    /** CSC Data Model 1.0.0 section 8.3: REQUIRED
     * Public access; the `type` discriminator is `public`.
     */
    @Serializable
    @SerialName("public")
    data object Public : AccessControlMethod()

    @Serializable
    @SerialName("OTP")
    data class OTP(
        /** CSC Data Model 1.0.0 section 8.3: REQUIRED
         * One-time password used to retrieve the document.
         */
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
