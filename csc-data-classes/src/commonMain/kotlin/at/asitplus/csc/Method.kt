package at.asitplus.csc

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry.DocumentLocationMethod

/**
 * After D3.1: UC Specification WP3.
 * Describes the restrictions/way of accessing a document
 *
 * This class serializes to
 * `{"type":"OTP","oneTimePassword":"1234"}`
 * `{"type":"public"}`
 * which is not to be confused with [DocumentLocationMethod] which instead serializes to
 * `{"document_access_mode":"OTP","oneTimePassword":"1234"}`
 * `{"document_access_mode":"public", "oneTimePassword": null}`
 *
 * but otherwise does the exact same thing. This was never unified.
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
    @SerialName("OTP")
    data class OTP(
        @SerialName("oneTimePassword")
        val oneTimePassword: String
    ) : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘Basic’ HTTP Authentication Scheme (RFC 7617).
     */
    @Serializable
    @SerialName("Basic_Auth")
    data object Basic : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘Digest’ HTTP Authentication Scheme (RFC 7616).
     */
    @Serializable
    @SerialName("Digest_Auth")
    data object Digest : Method()

    /**
     * D3.1: UC Specification WP3:
     * The wallet fetches the document from
     * [documentLocationUri]. The document should be fetched
     * using the ‘OAuth 2.0’ Authentication Framework (RFC6749
     * and RFC8252).
     */
    @Serializable
    @SerialName("OAuth_20")
    data object Oauth2 : Method()
}