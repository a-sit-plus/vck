package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

interface PathAuthorizationValidator {
    operator fun invoke(
        credential: SubjectCredentialStore.StoreEntry,
        attributePath: NormalizedJsonPath
    ): Boolean
}

class LambdaPathAuthorizationValidator(
    val evaluator: (
        credential: SubjectCredentialStore.StoreEntry,
        attributePath: NormalizedJsonPath,
    ) -> Boolean
) : PathAuthorizationValidator {
    override operator fun invoke(
        credential: SubjectCredentialStore.StoreEntry,
        attributePath: NormalizedJsonPath
    ): Boolean {
        return evaluator(
            credential,
            attributePath,
        )
    }
}