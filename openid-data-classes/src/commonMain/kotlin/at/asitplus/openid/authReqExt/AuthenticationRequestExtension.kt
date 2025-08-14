package at.asitplus.openid.authReqExt

import at.asitplus.openid.AuthenticationRequestParameters

sealed interface AuthenticationRequestExtension {
    fun fromSurrogate(authReqParam: AuthenticationRequestParameters): AuthenticationRequestExtension?
    fun isValid()
}