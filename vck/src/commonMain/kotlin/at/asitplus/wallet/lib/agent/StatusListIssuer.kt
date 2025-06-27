package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusIssuer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.StatusProvider
import kotlinx.datetime.Instant

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
     * Revokes all verifiable credentials from [credentialsToRevoke] list that parse and validate.
     * It returns true if all revocations was successful.
     */
    suspend fun revokeCredentials(credentialsToRevoke: List<String>): Boolean

    /**
     * Revokes all verifiable credentials with ids and issuance date from [credentialIdsToRevoke]
     * It returns true if all revocations was successful.
     */
    fun revokeCredentialsWithId(credentialIdsToRevoke: Map<String, Instant>): Boolean
}