package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.jsonpath.core.NormalizedJsonPath

@ConsistentCopyVisibility
data class IsoPresentationParameters private constructor(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val claims: Collection<NormalizedJsonPath>,
    val zkMetadata: ZkMetadata?
) {
    companion object {
        fun create(
            credential: SubjectCredentialStore.StoreEntry.Iso,
            claims: Collection<NormalizedJsonPath>,
            zkMetadata: ZkMetadata? = null,
        ): KmmResult<IsoPresentationParameters> = catching {
            if (zkMetadata?.isCompatibleWith(credential) == false) {
               throw PresentationException("Metadata incompatible with credential")
            }
            IsoPresentationParameters(credential, claims, zkMetadata)
        }
    }
}