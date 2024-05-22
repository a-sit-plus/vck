package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

fun interface PathAuthorizationValidator {
    operator fun invoke(
        credential: SubjectCredentialStore.StoreEntry,
        attributePath: NormalizedJsonPath
    ): Boolean
}