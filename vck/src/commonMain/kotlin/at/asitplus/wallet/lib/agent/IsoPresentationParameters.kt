package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.data.MdocClaimReference

@ConsistentCopyVisibility
data class IsoPresentationParameters private constructor(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val claims: Collection<MdocClaimReference>,
    val zkMetadata: ZkMetadata?
) {
    companion object {
        fun create(
            credential: SubjectCredentialStore.StoreEntry.Iso,
            claims: Collection<MdocClaimReference>,
            zkMetadata: ZkMetadata? = null,
        ): KmmResult<IsoPresentationParameters> = catching {
            if (zkMetadata?.isCompatibleWith(credential) == false) {
               throw PresentationException("Metadata incompatible with credential")
            }
            IsoPresentationParameters(credential, claims, zkMetadata)
        }
    }
}