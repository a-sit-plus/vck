package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.OpenIdConstants.Errors.ACCESS_DENIED
import at.asitplus.openid.OpenIdConstants.Errors.CREDENTIAL_REQUEST_DENIED
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_AUTHDETAILS
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_CLIENT
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_CODE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_CREDENTIAL_REQUEST
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_DPOP_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_ENCRYPTION_PARAMETERS
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_GRANT
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_NONCE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_PROOF
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_SCOPE
import at.asitplus.openid.OpenIdConstants.Errors.INVALID_TOKEN
import at.asitplus.openid.OpenIdConstants.Errors.REGISTRATION_VALUE_NOT_SUPPORTED
import at.asitplus.openid.OpenIdConstants.Errors.UNKNOWN_CREDENTIAL_CONFIGURATION
import at.asitplus.openid.OpenIdConstants.Errors.UNKNOWN_CREDENTIAL_IDENTIFIER
import at.asitplus.openid.OpenIdConstants.Errors.USER_CANCELLED
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.wallet.lib.data.vckJsonSerializer
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement

/**
 * OAuth2/OIDC error representation for issuer and wallet flows.
 * Use to model protocol errors and serialize them for responses.
 */
@Serializable
sealed class OAuth2Exception(
    val error: String,
    @Transient val errorDescription: String? = null,
) : Throwable("$error${errorDescription?.let { ": $it" }}") {

    fun serialize() = vckJsonSerializer.encodeToString(OAuth2ExceptionSerializer, this)

    /**
     * [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1): The request is missing a required
     * parameter, includes an unsupported parameter or parameter value, repeats the same parameter, uses more than one
     * method for including an access token, or is otherwise malformed.  The resource server SHOULD respond with the
     * HTTP 400 (Bad Request) status code.
     */
    @Serializable
    class InvalidRequest(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_REQUEST, description)

    @Serializable
    class InvalidClient(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_CLIENT, description)

    @Serializable
    class InvalidScope(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_SCOPE, description)

    @Serializable
    class InvalidGrant(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_GRANT, description)

    @Serializable
    class InvalidCode(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_CODE, description)

    /**
     * [RFC6750](https://datatracker.ietf.org/doc/html/rfc6750#section-3.1): The access token provided is expired,
     * revoked, malformed, or invalid for other reasons.  The resource SHOULD respond with the HTTP 401 (Unauthorized)
     * status code.  The client MAY request a new access token and retry the protected resource request.
     */
    @Serializable
    class InvalidToken(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_TOKEN, description), OAuthAuthorizationError

    @Serializable
    class InvalidProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_PROOF, description)

    @Serializable
    class UserCancelled(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(USER_CANCELLED, description)

    @Serializable
    class InvalidDpopProof(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_DPOP_PROOF, description), OAuthAuthorizationError

    @Serializable
    class UseDpopNonce(
        /** Set this as the value for HTTP header `DPoP-Nonce` in the response. */
        val dpopNonce: String,
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(USE_DPOP_NONCE, description), OAuthAuthorizationError

    @Serializable
    class InvalidCredentialRequest(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_CREDENTIAL_REQUEST, description)

    @Serializable
    class UnknownCredentialConfiguration(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(UNKNOWN_CREDENTIAL_CONFIGURATION, description)

    @Serializable
    class UnknownCredentialIdentifier(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(UNKNOWN_CREDENTIAL_IDENTIFIER, description)

    @Serializable
    class CredentialRequestDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(CREDENTIAL_REQUEST_DENIED, description)

    @Serializable
    class InvalidEncryptionParameters(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_ENCRYPTION_PARAMETERS, description)

    @Serializable
    class InvalidNonce(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_NONCE, description)

    @Serializable
    class AccessDenied(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(ACCESS_DENIED, description)

    @Serializable
    class RegistrationValueNotSupported(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(REGISTRATION_VALUE_NOT_SUPPORTED, description)

    @Serializable
    class InvalidAuthorizationDetails(
        @Transient val description: String? = null,
        @Transient override val cause: Throwable? = null
    ) : OAuth2Exception(INVALID_AUTHDETAILS, description)

    fun toOAuth2Error(): OAuth2Error = OAuth2Error(
        error = error,
        errorDescription = errorDescription ?: message,
    )
}

interface OAuthAuthorizationError {}

object OAuth2ExceptionSerializer : JsonContentPolymorphicSerializer<OAuth2Exception>(OAuth2Exception::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<OAuth2Exception> {
        throw NotImplementedError("Deserialization not supported")
    }
}
