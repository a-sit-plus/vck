package at.asitplus.wallet.lib.oidc

import io.ktor.http.*

sealed class AuthenticationRequestParametersFrom<T>(val source: T, val parameters: AuthenticationRequestParameters) {
    class JwsSigned(
        jwsSigned: at.asitplus.crypto.datatypes.jws.JwsSigned,
        parameters: AuthenticationRequestParameters
    ) : AuthenticationRequestParametersFrom<at.asitplus.crypto.datatypes.jws.JwsSigned>(jwsSigned, parameters)

    class Uri(url: Url, parameters: AuthenticationRequestParameters) :
        AuthenticationRequestParametersFrom<Url>(url, parameters)

    class Json(jsonString: String, parameters: AuthenticationRequestParameters) :
        AuthenticationRequestParametersFrom<String>(jsonString, parameters)
}