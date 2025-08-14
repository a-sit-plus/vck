package at.asitplus.openid.authReqExt

import kotlinx.serialization.Serializable

@Serializable
data class AuthReqnew(
    //Core elements are OAuth2 parameters
    val responseType: String?=null,
    val clientId: String? = null,
    val redirectUri: String? = null,
    val scope: String? = null,
    val state: String? = null,

    //Rest is extension
    val cscExtension: CscExtension?,
    val oidcExtension: String?,
    val oid4vpExtension: String?,
    val siopExtension: String?,
    val jarExtenstion: String?,
    val dcapiExtension: String?,
) {
    init {
        cscExtension?.isValid()

    }
}

