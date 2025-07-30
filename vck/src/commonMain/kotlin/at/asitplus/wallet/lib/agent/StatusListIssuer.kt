package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusProvider

/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface StatusListIssuer :
    StatusIssuer<JwsSigned<StatusListTokenPayload>, CoseSigned<StatusListTokenPayload>>,
    StatusProvider<StatusListToken> {

    /**
     * Returns a status list as defined in [TokenListStatus](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html)
     */
    fun buildStatusList(timePeriod: Int? = null): StatusList?

    /**
     * Sets the status of one specific credential to [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus.Invalid].
     * Returns true if this credential has been revoked.
     */
    fun revokeCredential(timePeriod: Int, statusListIndex: ULong): Boolean

}