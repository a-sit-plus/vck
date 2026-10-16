package at.asitplus.wallet.lib.openid

import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.wallet.lib.oidvci.OAuth2Error

/**
 * The authorization error response (OpenID4VP 1.0, 8.2, 8.5, A.4) in the effective parameters of [this], i.e. after
 * decryption, or `null` if the wallet presented, i.e. answered without `error`.
 *
 * Error codes are not limited to a fixed set (OpenID4VP 1.0, 8.5), but their syntax must follow
 * [RFC 6749, 4.1.2.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1). Over the Digital Credentials API,
 * an error carries `error` only (OpenID4VP 1.0, A.4), which is a special case of the same rules.
 *
 * @throws IllegalArgumentException for malformed combinations of parameters
 */
@Throws(IllegalArgumentException::class)
internal fun ResponseParametersFrom.authorizationError(): OAuth2Error? {
    val envelope = originalResponseParameters
    if (envelope !== this) {
        // the content of an encoded response is in the JWT only, so nothing may be mixed in next to it
        with(envelope.parameters) {
            require(listOf(error, errorDescription, errorUri, vpToken, code).all { it == null }) {
                "Response parameters must not be passed next to an encoded response"
            }
        }
    }
    with(parameters) {
        val error = error ?: run {
            require(errorDescription == null && errorUri == null) {
                "error_description and error_uri require error"
            }
            return null
        }
        require(vpToken == null && code == null) {
            "error must not be combined with vp_token or code"
        }
        require(error.isNotBlank() && error.all { it.isErrorChar() }) {
            "error is blank or contains characters not allowed by RFC 6749"
        }
        require(errorDescription?.all { it.isErrorChar() } != false) {
            "error_description contains characters not allowed by RFC 6749"
        }
        require(errorUri?.all { it.isErrorUriChar() } != false) {
            "error_uri contains characters not allowed by RFC 6749"
        }
        return OAuth2Error(error, errorDescription, errorUri, state)
    }
}

/** RFC 6749, 4.1.2.1: `%x20-21 / %x23-5B / %x5D-7E`, for `error` and `error_description`. */
private fun Char.isErrorChar() = this in ' '..'!' || this in '#'..'[' || this in ']'..'~'

/** RFC 6749, 4.1.2.1: `%x21 / %x23-5B / %x5D-7E`, for `error_uri`, i.e. without the space. */
private fun Char.isErrorUriChar() = this != ' ' && isErrorChar()
