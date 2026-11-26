package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.CredentialRenewalInfo
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PreparedCredentialStorage
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.ValidationPolicy
import kotlin.jvm.JvmOverloads

/**
 * A credential of a credential response, see [OpenId4VciClient.decodeCredentialResponse]. It has not been validated:
 * pass it to [prepareCredentialStorage], which validates it with the holder's key and validator.
 */
sealed interface ReceivedCredential {

    /**
     * A credential decoded from its encoding in the credential response (OpenID4VCI 1.0, Appendix A), with the
     * [proofKeys] and [holderBindingRequired] of the request it was issued for, see
     * [OpenId4VciClient.CredentialRequest].
     */
    data class Decoded @JvmOverloads constructor(
        val input: CredentialValidationInput,
        val proofKeys: Set<CryptoPublicKey> = emptySet(),
        val holderBindingRequired: Boolean = true,
    ) : ReceivedCredential

    /**
     * A credential that could not be decoded from its encoding in the credential response, e.g. an mdoc that is no
     * base64url (OpenID4VCI 1.0, A.2.4). It is reported as rejected, see [HolderAgent.rejectUndecodable].
     */
    data class Undecodable(val cause: Throwable) : ReceivedCredential

    /**
     * Validates this credential of the type of [scheme] for storage by [holder] under [policy], with [renewalInfo],
     * see [HolderAgent.prepareCredentialStorageBoundTo], and stores nothing yet. It has to be bound to one of the
     * [Decoded.proofKeys], or to no key unless [Decoded.holderBindingRequired]. A credential that could not be decoded
     * is prepared as rejected, so that it is reported like every other credential of a batch, but can never be stored.
     *
     * Fails if [scheme] does not support the representation of the credential.
     */
    suspend fun prepareCredentialStorage(
        holder: HolderAgent,
        scheme: CredentialScheme,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<PreparedCredentialStorage> = when (this) {
        is Decoded -> policy.copy(
            holderBinding = if (holderBindingRequired) HolderBindingPolicy.RequireExpectedKey
            else HolderBindingPolicy.RequireNoKey
        ).let { bindingPolicy ->
            if (!holderBindingRequired || proofKeys.isNotEmpty()) holder.prepareCredentialStorageBoundTo(
                input = input,
                scheme = scheme,
                policy = bindingPolicy,
                expectedHolderKeys = proofKeys,
                renewalInfo = renewalInfo,
            )
            // The key of the proof is unknown, e.g. for a proof creator that implements only `invoke`: a holder with
            // one key expects its key, any other holder fails, as it can not know which key to expect
            else @Suppress("DEPRECATION") holder.prepareCredentialStorage(
                input = input,
                scheme = scheme,
                policy = bindingPolicy,
                renewalInfo = renewalInfo,
            )
        }
        is Undecodable -> KmmResult.success(holder.rejectUndecodable(cause, policy, renewalInfo))
    }
}
