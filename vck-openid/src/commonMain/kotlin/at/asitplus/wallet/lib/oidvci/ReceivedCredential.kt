package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PreparedCredentialStorage
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.ValidationPolicy

/**
 * A credential of a credential response, see [OpenId4VciClient.decodeCredentialResponse]. It has not been validated:
 * pass it to [prepareCredentialStorage], which validates it with the holder's key and validator.
 */
sealed interface ReceivedCredential {

    /** A credential decoded from its encoding in the credential response (OpenID4VCI 1.0, Appendix A). */
    data class Decoded(val input: CredentialValidationInput) : ReceivedCredential

    /**
     * A credential that could not be decoded from its encoding in the credential response, e.g. an mdoc that is no
     * base64url (OpenID4VCI 1.0, A.2.4). It is reported as rejected, see [HolderAgent.rejectUndecodable].
     */
    data class Undecodable(val cause: Throwable) : ReceivedCredential

    /**
     * Validates this credential of the type of [scheme] for storage by [holder] under [policy], with [renewalInfo],
     * see [HolderAgent.prepareCredentialStorage], and stores nothing yet. A credential that could not be decoded is
     * prepared as rejected, so that it is reported like every other credential of a batch, but can never be stored.
     *
     * Fails if [scheme] does not support the representation of the credential.
     */
    suspend fun prepareCredentialStorage(
        holder: HolderAgent,
        scheme: CredentialScheme,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<PreparedCredentialStorage> = when (this) {
        is Decoded -> holder.prepareCredentialStorage(input, scheme, policy, renewalInfo)
        is Undecodable -> KmmResult.success(holder.rejectUndecodable(cause, policy, renewalInfo))
    }
}
