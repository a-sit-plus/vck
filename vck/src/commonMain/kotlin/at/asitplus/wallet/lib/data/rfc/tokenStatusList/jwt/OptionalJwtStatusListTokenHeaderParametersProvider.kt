package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenHeader
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.MissingHeaderParameterException
import at.asitplus.wallet.lib.data.rfc7519.jwt.headers.JwtTypeHeaderParameterSpecification
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * The following content applies to the JWT Header:
 *
 * typ: REQUIRED. The JWT type MUST be statuslist+jwt.
 */
interface OptionalJwtStatusListTokenHeaderParametersProvider : JwtTypeHeaderParameterSpecification.ParameterProvider {
    val containsStatusListTokenHeader: Boolean
        get() = typ == JwsContentTypeConstants.STATUSLIST_JWT

    fun toStatusListTokenHeader() = if(typ == JwsContentTypeConstants.STATUSLIST_JWT) {
        StatusListTokenHeader(
            type = typ ?: throw MissingHeaderParameterException(JwtTypeHeaderParameterSpecification.NAME),
        )
    } else {
        throw IllegalStateException("Member `${JwtTypeHeaderParameterSpecification.NAME}` must have the value `${JwsContentTypeConstants.STATUSLIST_JWT}`.")
    }
}

