package at.asitplus.dif.rqes

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * After D3.1: UC Specification WP3.
 * However, this class is potentially a mistake in the draft spec vs test vector,
 * currently we need it to be a sealed class with polymorphic serialization to get the structure
 * `method: {type: NAME}`
 * sealed class would instead serialize to
 * `method: NAME`
 * which might be the corrected implementation in the next draft.
 *
 * The method describes the restrictions/way of accessing a document
 */
@Serializable
@SerialName("method")
sealed class Method {
    /**
     * D3.1: UC Specification WP3:
     * The document corresponding to the parameter [hash] can be
     * fetched from [documentLocationUri] with a https-request
     * without further restrictions.
     */
    @Serializable
    @SerialName("public")
    data object Public : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet displays the parameter [oneTimePassword] to the
     * user. A webclient accessing the uri offers a way for the user to
     * input the shown value and only then allows to fetch the
     * document corresponding to [hash].
     */
    @Serializable
    @SerialName("otp")
    data class OTP(
        val oneTimePassword: String
    ) : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘Basic’ HTTP Authentication Scheme (RFC 7617).
     */
    @Serializable
    @SerialName("basic_auth")
    data object Basic : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘Digest’ HTTP Authentication Scheme (RFC 7616).
     */
    @Serializable
    @SerialName("digest_auth")
    data object Digest : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘OAuth 2.0’ Authentication Framework (RFC6749
     * and RFC8252).
     */
    @Serializable
    @SerialName("oauth_20")
    data object Oauth2 : Method()
}