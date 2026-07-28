package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.jsonpath.core.NormalizedJsonPath

@ConsistentCopyVisibility
data class IsoPresentationParameters private constructor(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val claims: Collection<NormalizedJsonPath>,
    val zkMetadata: ZkMetadata?
) {
    constructor(
        credential: SubjectCredentialStore.StoreEntry.Iso,
        claims: Collection<NormalizedJsonPath>
    ) : this(credential, claims, null)

    companion object {
        fun create(
            credential: SubjectCredentialStore.StoreEntry.Iso,
            claims: Collection<NormalizedJsonPath>,
            zkMetadata: ZkMetadata?
        ): KmmResult<IsoPresentationParameters> {
            if (zkMetadata?.isCompatibleWith(credential) == false) {
                return KmmResult.failure(PresentationException("Metadata incompatible with credential"))
            }
            return KmmResult.success(IsoPresentationParameters(credential, claims, zkMetadata))
        }
    }
}