package at.asitplus.wallet.lib.agent

import at.asitplus.jsonpath.core.NormalizedJsonPath

interface PathAuthorizationValidator {
    operator fun invoke(
        credential: SubjectCredentialStore.StoreEntry,
        attribute: NormalizedJsonPath
    ): Boolean
}

class LambdaPathAuthorizationValidator(
    val evaluator: (
        credential: SubjectCredentialStore.StoreEntry,
        attribute: NormalizedJsonPath,
    ) -> Boolean
) : PathAuthorizationValidator {
    override operator fun invoke(
        credential: SubjectCredentialStore.StoreEntry,
        attribute: NormalizedJsonPath
    ): Boolean {
        return evaluator(
            credential,
            attribute,
        )
    }
}