package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

data class IsoPresentation(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val paths: Collection<NormalizedJsonPath>,
    val meta: PresentationMetadata? = null
)
