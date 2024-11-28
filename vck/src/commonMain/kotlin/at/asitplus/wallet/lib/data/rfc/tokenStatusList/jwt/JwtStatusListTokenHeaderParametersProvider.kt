package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * The following content applies to the JWT Header:
 *
 * typ: REQUIRED. The JWT type MUST be statuslist+jwt.
 */
interface JwtStatusListTokenHeaderParametersProvider : OptionalJwtStatusListTokenHeaderParametersProvider {
    override val typ: String

    override val containsStatusListTokenHeader: Boolean
        get() = true
}

