package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusProvider

/**
 * Summarizes operations for an Issuer in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can issue Verifiable Credentials, revoke credentials and build a revocation list.
 */
interface StatusListIssuer :
    StatusIssuer<JwsSigned<StatusListTokenPayload>, CoseSigned<ByteArray>>,
    StatusProvider<StatusListToken> {

    /**
     * Returns a revocation list which can either be
     * status list as defined in [TokenListStatus](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html)
     * or an identifier list as defined in ISO18013-5
     */
    fun buildRevocationList(timePeriod: Int? = null, kind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST): RevocationList?

    /**
     * Sets the status of one specific credential to [at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus.Invalid].
     * Returns true if this credential has been revoked.
     */
    fun revokeCredential(timePeriod: Int, statusListIndex: ULong): Boolean

}