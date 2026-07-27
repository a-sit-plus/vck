package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.jsonpath.core.NormalizedJsonPath

@ConsistentCopyVisibility
data class IsoPresentation private constructor(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val paths: Collection<NormalizedJsonPath>,
    val meta: PresentationMetadata?
) {
    constructor(
        credential: SubjectCredentialStore.StoreEntry.Iso,
        paths: Collection<NormalizedJsonPath>
    ) : this(credential, paths, null)

    companion object {
        fun create(
            credential: SubjectCredentialStore.StoreEntry.Iso,
            paths: Collection<NormalizedJsonPath>,
            meta: PresentationMetadata?
        ): KmmResult<IsoPresentation> {
            if (meta?.isCompatibleWith(credential) == false) {
                return KmmResult.failure(PresentationException("Metadata incompatible with credential"))
            }
            return KmmResult.success(IsoPresentation(credential, paths, meta))
        }
    }
}