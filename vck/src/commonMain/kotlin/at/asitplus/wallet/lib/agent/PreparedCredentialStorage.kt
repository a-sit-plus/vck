package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.validation.CredentialValidationResult

/**
 * A received [credential] with its [validation], before it is stored, see [HolderAgent.prepareCredentialStorage]:
 * keep it while the user looks at the report, then pass it to [HolderAgent.storeAccepted], or, if the user accepts a
 * rejected report, to [HolderAgent.storeAfterUserConsent].
 *
 * Only a [HolderAgent] creates it, so the validation always belongs to the credential and to the holder's key.
 */
@ConsistentCopyVisibility
data class PreparedCredentialStorage internal constructor(
    /**
     * The credential to store, `null` if it has been validated from its encoding, but is not intact, e.g. if it can
     * not be decoded, see [HolderAgent.rejectUndecodable], and thus can never be stored.
     */
    val credential: Holder.StoreCredentialInput?,
    val validation: CredentialValidationResult,
    val renewalInfo: CredentialRenewalInfo?,
    /**
     * The key the credential is bound to, `null` if it is not intact, not holder-bound, or bound to a key that can not be
     * read, e.g. an SD-JWT VC whose `cnf` has a `kid` instead of a `jwk`; see
     * [SubjectCredentialStore.StoreEntry.isHolderBound] to tell the last two apart.
     */
    val holderKey: CryptoPublicKey?,
) {
    init {
        require(credential != null || validation.unacceptedCredential == null) {
            "An intact credential is prepared with the credential to store"
        }
    }
}
