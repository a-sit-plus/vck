package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
 *
 * The following content applies to the CWT protected header:
 *
 * 16 (type): REQUIRED. The type of the CWT MUST be statuslist+cwt as defined in [RFC9596].
 */
interface CwtStatusListTokenHeaderParametersProvider :
    OptionalCwtStatusListTokenHeaderParametersProvider {
    override val typ: String

    override val containsStatusListTokenHeader: Boolean
        get() = true
}

