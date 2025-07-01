package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

@Serializable
sealed class OAuth2Exception(
    val error: String,
    @Transient val errorDescription: String? = null,
) : Throwable("$error${errorDescription?.let { ": $it" }}") {

    fun serialize() = vckJsonSerializer.encodeToString(OAuth2ExceptionSerializer, this)

    @Serializable
    class InvalidRequest(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST, description)

    @Serializable
    class InvalidClient(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_CLIENT, description)

    @Serializable
    class InvalidScope(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_SCOPE, description)

    @Serializable
    class InvalidGrant(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_GRANT, description)

    @Serializable
    class InvalidCode(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_CODE, description)

    @Serializable
    class InvalidToken(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_TOKEN, description)

    @Serializable
    class InvalidProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_PROOF, description)

    @Serializable
    class UserCancelled(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.USER_CANCELLED, description)

    @Serializable
    class InvalidDpopProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_DPOP_PROOF, description)

    @Serializable
    class UnsupportedCredentialType(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.UNSUPPORTED_CREDENTIAL_TYPE, description)

    @Serializable
    class CredentialRequestDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.CREDENTIAL_REQUEST_DENIED, description)

    @Serializable
    class InvalidNonce(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_NONCE, description)

    @Serializable
    class AccessDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.ACCESS_DENIED, description)

    @Serializable
    class RegistrationValueNotSupported(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.REGISTRATION_VALUE_NOT_SUPPORTED, description)

    @Serializable
    class InvalidAuthorizationDetails(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(OpenIdConstants.Errors.INVALID_AUTHDETAILS, description)
}
object OAuth2ExceptionSerializer : JsonContentPolymorphicSerializer<OAuth2Exception>(OAuth2Exception::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<OAuth2Exception> {
        throw NotImplementedError("Deserialization not supported")
    }
}
